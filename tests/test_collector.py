import contextlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import space_search_collector as c


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        c.COLLECT_SINK.clear()
        c._CURRENT_MODULE = None
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.sleep = self.stack.enter_context(patch.object(c.time, 'sleep'))

    def response(self, payload):
        return 200, json.dumps(payload)

    def hunter_config(self, **extra):
        return dict(url='https://example.test', query='test', keys=['secret-a', 'secret-b'], **extra)

    def quake_config(self, **extra):
        return dict(url='https://example.test', query='a OR b', keys=['secret-a'], **dict({'cidr': False}, **extra))

    def fofa_config(self, **extra):
        return dict(url='https://example.test', email='test@example.test', token='secret',
                    query='test', interval=0, state_dir=str(self.root / 'state'), **dict({'run_mode': 'fixed'}, **extra))

    def row(self):
        return c._fofa_parse_row(['https://example.test', '192.0.2.1', 443, 'https'])

    def test_tls_verification_enabled(self):
        self.assertTrue(c.CTX.check_hostname)
        self.assertEqual(c.CTX.verify_mode, ssl.CERT_REQUIRED)

    def test_keys_accept_string_and_deduplicate(self):
        self.assertEqual(c._resolve_keys({}), [])
        self.assertEqual(c._resolve_keys({'keys': 'key'}), ['key'])
        self.assertEqual(c._resolve_keys({'keys': ['key', 'key', ' ']}), ['key'])

    def test_hunter_exhausted_keys_stop(self):
        with patch.object(c, 'http_get', return_value=self.response({'code': 40204})) as http:
            self.assertEqual(c.search_hunter(self.hunter_config()), [])
            self.assertEqual(http.call_count, 2)

    def test_hunter_quota_switch_same_page(self):
        pages = [self.response({'code': 40204}), self.response({'code': 200, 'data': {
            'arr': [{'url': 'https://example.test'}], 'total': 1}})]
        with patch.object(c, 'http_get', side_effect=pages) as http:
            self.assertEqual(len(c.search_hunter(self.hunter_config())), 1)
            self.assertEqual([call.kwargs['params']['page'] for call in http.call_args_list], [1, 1])
            self.assertEqual([call.kwargs['params']['api-key'] for call in http.call_args_list], ['secret-a', 'secret-b'])

    def test_hunter_rate_limit_bounded(self):
        with patch.object(c, 'http_get', return_value=self.response({'code': 429, 'message': '请求太多'})) as http:
            c.search_hunter(self.hunter_config())
            self.assertEqual(http.call_count, 10)

    def test_hunter_size_exact(self):
        rows = [{'url': f'https://example.test:{i + 80}'} for i in range(5)]
        with patch.object(c, 'http_get', return_value=self.response({'code': 200, 'data': {'arr': rows}})):
            self.assertEqual(len(c.search_hunter(self.hunter_config(all=False, size=2))), 2)

    def test_hunter_does_not_log_key_prefix(self):
        with patch.object(c, 'http_get', return_value=self.response({'code': 40204})), patch.object(c, 'log') as logger:
            c.search_hunter(self.hunter_config())
            self.assertNotIn('secret-', str(logger.call_args_list))

    def test_quake_rate_limit_bounded(self):
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 'q2003', 'message': '限流'})) as http:
            c.search_quake(self.quake_config())
            self.assertEqual(http.call_count, 10)

    def test_quake_request_respects_remaining_size(self):
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 0, 'data': []})) as http:
            c.search_quake(self.quake_config(size=1, all=False))
            self.assertEqual(http.call_args.args[1]['size'], 1)

    def test_partition_groups_base_query(self):
        queries = c._build_quake_queries(self.quake_config(partition={'geo': [{'country': '美国'}]}))
        self.assertEqual(queries, ['(a OR b) && country:"美国"'])

    def test_adaptive_accepts_base_query_alias(self):
        cfg = self.quake_config()
        cfg['base_query'] = cfg.pop('query')
        with patch.object(c, '_quake_fetch_page', return_value=None):
            self.assertEqual(c._adaptive_quake_queries(cfg, cfg['url'], ['key'], True, 500), ['(a OR b)'])

    def test_history_preserves_https_and_ipv6(self):
        path = self.root / 'assets'
        path.write_text('https://example.test:443\nhttps://[2001:db8::1]:8443\n')
        merged = c.merge_and_dedup(c._load_previous_urls(path))
        self.assertEqual([c.format_url(m) for m in merged], path.read_text().splitlines())

    def test_dedup_combines_sources(self):
        rows = [{'host': host, 'source': source} for host, source in
                [('https://EXAMPLE.test', 'fofa'), ('https://example.test:443', 'hunter')]]
        merged = c.merge_and_dedup(rows)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['sources'], {'fofa', 'hunter'})

    def test_invalid_port_rejected(self):
        self.assertIsNone(c.parse_url_key({'host': 'example.test', 'port': -1}))

    def test_atomic_write_failure_preserves_file(self):
        path = self.root / 'assets'
        path.write_text('old')
        with self.assertRaises(OSError), patch.object(c.os, 'replace', side_effect=OSError('disk error')):
            with c._atomic_text_file(path) as f:
                f.write('new')
        self.assertEqual(path.read_text(), 'old')
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_fofa_completed_checkpoint_reusable_without_network(self):
        cfg = self.fofa_config()
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)) as http:
            first = c.search_fofa(cfg)
            second = c.search_fofa(cfg)
            self.assertEqual(first, second)
            self.assertEqual(http.call_count, 1)
        self.assertTrue((self.root / 'state/state.json').exists())

    def test_fofa_mismatch_preserves_checkpoint(self):
        cfg = self.fofa_config()
        with patch.object(c, '_fofa_query', return_value=([], 0, 1)):
            c.search_fofa(cfg)
        state = self.root / 'state/state.json'
        before = state.read_bytes()
        with self.assertRaises(ValueError):
            c._fofa_load_state(cfg['state_dir'], 'different')
        self.assertEqual(state.read_bytes(), before)
        with self.assertRaises(ValueError):
            c._fofa_load_state(cfg['state_dir'], cfg['query'], True)

    def test_fofa_missing_part_does_not_silently_drop_assets(self):
        cfg = self.fofa_config()
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)):
            c.search_fofa(cfg)
        next((self.root / 'state/parts').iterdir()).unlink()
        with self.assertRaises(ValueError):
            c.search_fofa(cfg)
        self.assertTrue((self.root / 'state/state.json').exists())

    def test_fofa_truncated_response_retains_pending_node(self):
        cfg = self.fofa_config()
        with patch.object(c, '_fofa_query', return_value=([self.row()], 2, 1)), self.assertRaises(c.FofaRequestError):
            c.search_fofa(cfg)
        state = json.loads((self.root / 'state/state.json').read_text())
        self.assertEqual(state['pending'], [[0, 0]])

    def test_fofa_single_ip_overflow_saves_returned_rows(self):
        cfg = self.fofa_config()
        state_dir = self.root / 'state'
        (state_dir / 'parts').mkdir(parents=True)
        c._atomic_write_json(state_dir / 'state.json', {
            'base_query': 'test', 'pending': [[0, 32]], 'completed': [], 'requests': 0})
        with patch.object(c, '_fofa_query', return_value=([self.row()], c.FOFA_LIMIT + 1, 1)):
            self.assertEqual(len(c.search_fofa(cfg)), 1)
        self.assertEqual(len(list((state_dir / 'parts').iterdir())), 1)

    def test_config_validation_precedes_api_calls(self):
        cfg = {'module': {'hunter': self.hunter_config(pageSize=0)}}
        with patch.object(c, 'http_get') as http, self.assertRaises(ValueError):
            c.run_collect(cfg)
        http.assert_not_called()

    def test_output_log_cannot_collide(self):
        with self.assertRaises(ValueError):
            c.run_collect({'module': {'hunter': self.hunter_config()}}, output_file='same', log_file='same')

    def test_interrupted_collection_saves_partial_and_history(self):
        output, logfile = self.root / 'assets', self.root / 'log'
        output.write_text('https://old.test:443\n')
        def interrupted(cfg):
            c._module_results().append({'host': 'https://new.test', 'source': 'hunter'})
            raise KeyboardInterrupt
        with patch.dict(c.MODULE_HANDLERS, {'hunter': interrupted}):
            result = c.run_collect({'module': {'hunter': self.hunter_config()}}, output, logfile)
        self.assertEqual(len(result), 2)
        self.assertEqual(set(output.read_text().splitlines()), {'https://old.test:443', 'https://new.test:443'})
        self.assertIsNone(c._CURRENT_MODULE)

    def test_sources_default_all(self):
        modules = {name: {} for name in ('fofa', 'hunter', 'quake')}
        self.assertEqual(c._select_modules(modules, 'all'), modules)

    def test_sources_single_pair_and_commas(self):
        modules = {name: {} for name in ('fofa', 'hunter', 'quake')}
        for selected in ('fofa', ['fofa', 'quake'], 'FOFA,quake'):
            expected = ['fofa'] if selected == 'fofa' else ['fofa', 'quake']
            self.assertEqual(list(c._select_modules(modules, selected)), expected)

    def test_sources_invalid_or_missing_rejected(self):
        for selected in ('other', 'all,fofa', 'fofa,', 'quake'):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                c._select_modules({'fofa': {}}, selected)

    def test_source_filter_excludes_validation_and_calls(self):
        config = {'sources': 'hunter', 'module': {'fofa': {}, 'hunter': self.hunter_config(), 'quake': {}}}
        with patch.dict(c.MODULE_HANDLERS, {name: unittest.mock.Mock(return_value=[]) for name in ('fofa', 'hunter', 'quake')}):
            c.run_collect(config, self.root / 'out', self.root / 'log')
            c.MODULE_HANDLERS['hunter'].assert_called_once()
            c.MODULE_HANDLERS['fofa'].assert_not_called()
            c.MODULE_HANDLERS['quake'].assert_not_called()

    def test_cli_source_overrides_config(self):
        config = {'sources': 'quake', 'module': {'hunter': self.hunter_config(), 'quake': {}}}
        with patch.dict(c.MODULE_HANDLERS, {'hunter': unittest.mock.Mock(return_value=[]), 'quake': unittest.mock.Mock()}):
            c.run_collect(config, self.root / 'out', self.root / 'log', sources=['hunter'])
            c.MODULE_HANDLERS['hunter'].assert_called_once()
            c.MODULE_HANDLERS['quake'].assert_not_called()

    def test_cli_passes_sources(self):
        for args, expected in (([], None), (['-s', 'fofa', 'hunter'], ['fofa', 'hunter']),
                               (['--sources', 'fofa,quake'], ['fofa,quake'])):
            with patch('sys.argv', ['collector'] + args), patch.object(c, 'ensure_config', return_value=True), \
                 patch.object(c, 'load_config', return_value={}), patch.object(c, 'run_collect', return_value=[{}]) as run:
                self.assertEqual(c.main(), 0)
                self.assertEqual(run.call_args.kwargs['sources'], expected)

    def test_quake_all_does_not_stop_at_size(self):
        pages = [self.response({'code': 0, 'data': [{'ip': '192.0.2.1', 'port': 80}],
                                'meta': {'pagination': {'total': 2}}}),
                 self.response({'code': 0, 'data': [{'ip': '192.0.2.2', 'port': 80}],
                                'meta': {'pagination': {'total': 2}}})]
        with patch.object(c, 'http_post_json', side_effect=pages) as http:
            result = c.search_quake(self.quake_config(all=True, size=1, pageSize=1, interval=0))
            self.assertEqual(len(result), 2)
            self.assertEqual([call.args[1]['start'] for call in http.call_args_list], [0, 1])

    def test_quake_page_limit_does_not_probe_all_keys(self):
        cfg = self.quake_config(pageSize=1, interval=0)
        cfg['keys'] = [f'key-{i}' for i in range(30)]
        with patch.object(c, 'http_post_json', return_value=self.response({
                'code': 'q2001', 'message': '最大允许翻页限制'})) as http:
            self.assertEqual(c.search_quake(cfg), [])
            self.assertEqual(http.call_count, 1)

    def test_quake_quota_failure_switches_key(self):
        cfg = self.quake_config()
        cfg['keys'] = ['empty', 'working']
        with patch.object(c, 'http_post_json', side_effect=[
            self.response({'code': 'q2002', 'message': '积分不足'}),
            self.response({'code': 0, 'data': []})]) as http:
            c.search_quake(cfg)
            self.assertEqual([call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list], ['empty', 'working'])

    def test_quake_rate_limit_visits_every_key(self):
        cfg = self.quake_config()
        cfg['keys'] = [f'key-{i}' for i in range(30)]
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 'q2003', 'message': '限流'})) as http:
            c.search_quake(cfg)
            visited = {call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list}
            self.assertEqual(visited, set(cfg['keys']))
            self.assertEqual(http.call_count, 90)

    def test_adaptive_sampling_switches_failed_key(self):
        with patch.object(c, '_quake_fetch_page', side_effect=[None, {'code': '0', 'data': []}]) as http:
            c._adaptive_quake_queries(self.quake_config(), 'url', ['empty', 'working'], True, 500)
            self.assertEqual([call.args[1] for call in http.call_args_list], ['empty', 'working'])

    def test_adaptive_covers_unsampled_provinces_and_ports(self):
        sample = {'code': 0, 'data': [
            {'ip': '192.0.2.1', 'port': 80, 'location': {'country_cn': '中国', 'province_cn': '北京'}},
            {'ip': '192.0.2.2', 'port': 443, 'location': {'country_cn': '美国'}}],
            'meta': {'pagination': {'total': 10000}}}
        with patch.object(c, '_quake_fetch_page', return_value=sample):
            queries = c._adaptive_quake_queries(self.quake_config(), 'url', ['key'], True, 500)
        self.assertIn('(a OR b) && country:"中国" && NOT (province:"北京")', queries)
        self.assertIn('(a OR b) && country:"美国" && NOT (port:443)', queries)
        self.assertTrue(any('NOT (country:' in query for query in queries))

    def test_hunter_permission_key_tried_once_and_working_key_kept(self):
        cfg = self.hunter_config(pageSize=1)
        cfg['keys'] = ['no-permission', 'working']
        pages = [self.response({'code': 400, 'message': '账号无 API 访问权限，需升级为付费账号'}),
                 self.response({'code': 200, 'data': {'arr': [{'url': 'https://one.test'}], 'total': 2}}),
                 self.response({'code': 200, 'data': {'arr': [{'url': 'https://two.test'}], 'total': 2}}),
                 self.response({'code': 200, 'data': {'arr': [], 'total': 2}})]
        with patch.object(c, 'http_get', side_effect=pages) as http:
            self.assertEqual(len(c.search_hunter(cfg)), 2)
            self.assertEqual([call.kwargs['params']['api-key'] for call in http.call_args_list],
                             ['no-permission', 'working', 'working', 'working'])

    def test_hunter_all_permission_denied_is_linear(self):
        cfg = self.hunter_config()
        cfg['keys'] = [f'key-{i}' for i in range(34)]
        with patch.object(c, 'http_get', return_value=self.response({
                'code': 400, 'message': '账号无 API 访问权限，需升级为付费账号'})) as http:
            c.search_hunter(cfg)
            self.assertEqual(http.call_count, 34)
            self.assertEqual(len({call.kwargs['params']['api-key'] for call in http.call_args_list}), 34)

    def test_quake_timeout_shrinks_page_and_retries_same_offset(self):
        cfg = self.quake_config(pageSize=4, timeout=12, interval=0)
        cfg['keys'] = ['first', 'second']
        pages = [(-1, 'timeout'), self.response({'code': 0, 'data': [
            {'ip': '192.0.2.1', 'port': 80}, {'ip': '192.0.2.2', 'port': 80}],
            'meta': {'pagination': {'total': 3}}}), self.response({'code': 0, 'data': [
            {'ip': '192.0.2.3', 'port': 80}], 'meta': {'pagination': {'total': 3}}})]
        with patch.object(c, 'http_post_json', side_effect=pages) as http:
            self.assertEqual(len(c.search_quake(cfg)), 3)
            self.assertEqual([call.args[1]['start'] for call in http.call_args_list], [0, 0, 2])
            self.assertEqual([call.args[1]['size'] for call in http.call_args_list], [4, 2, 2])
            self.assertEqual([call.kwargs['timeout'] for call in http.call_args_list], [12, 12, 12])
            self.assertEqual(http.call_args_list[1].kwargs['headers']['X-QuakeToken'], 'second')

    def test_quake_network_outage_is_bounded_without_dead_key_claim(self):
        with patch.object(c, 'http_post_json', return_value=(-1, 'timeout')) as http, patch.object(c, 'log') as logger:
            c.search_quake(self.quake_config(retries=2))
            self.assertEqual(http.call_count, 3)
            self.assertNotIn('HTTP 连续失败, 弃用', str(logger.call_args_list))
            self.assertIn('不判定 key 失效', str(logger.call_args_list))

    def test_quake_waiting_heartbeat_and_cleanup(self):
        observed = c.Event()
        messages = []
        def record(message):
            messages.append(message)
            if '等待响应' in message:
                observed.set()
        def blocked_request(*args, **kwargs):
            self.assertTrue(observed.wait(1), '请求未返回时应输出等待状态')
            return self.response({'code': 0, 'data': []})
        payload = {'query': 'test', 'start': 0, 'size': 100}
        with patch.object(c, 'QUAKE_HEARTBEAT_SECONDS', 0.01), patch.object(c, 'log', side_effect=record), \
             patch.object(c, 'http_post_json', side_effect=blocked_request):
            self.assertEqual(c._quake_request('url', payload, 'SECRET', '#1', '采集', 30)[0], 200)
        self.assertIn('开始请求', messages[0])
        self.assertTrue(any('等待响应' in message for message in messages))
        self.assertIn('成功', messages[-1])
        self.assertNotIn('SECRET', '\n'.join(messages))
        import threading
        self.assertFalse(any(thread.name == 'quake-progress' for thread in threading.enumerate()))

    def test_quake_reports_permission_and_quota_without_secret(self):
        payload = {'query': 'test', 'start': 0, 'size': 100}
        for response, expected in (({'code': 'q2001', 'message': '权限不足 SECRET'}, '账号无搜索权限'),
                                   ({'code': 'q2002', 'message': '额度不足 SECRET'}, '额度不足')):
            with self.subTest(expected=expected), patch.object(c, 'log') as logger, \
                 patch.object(c, 'http_post_json', return_value=self.response(response)):
                c._quake_request('url', payload, 'SECRET', '#2', '采样', 30)
                self.assertIn(expected, str(logger.call_args_list))
                self.assertNotIn('SECRET', str(logger.call_args_list))

    def test_quake_interrupt_stops_heartbeat(self):
        with patch.object(c, 'http_post_json', side_effect=KeyboardInterrupt), patch.object(c, 'log') as logger:
            with self.assertRaises(KeyboardInterrupt):
                c._quake_request('url', {'start': 0, 'size': 100}, 'secret', '#1', '采集', 30)
            self.assertIn('请求中断', str(logger.call_args_list))
        import threading
        self.assertFalse(any(thread.name == 'quake-progress' for thread in threading.enumerate()))

    def test_network_error_categories_are_credential_safe(self):
        import socket
        import urllib.error
        for error, expected in ((TimeoutError('SECRET'), '超时'),
                                (urllib.error.URLError(socket.gaierror('SECRET')), 'DNS'),
                                (ssl.SSLCertVerificationError('SECRET'), '证书'),
                                (ConnectionResetError('SECRET'), '连接')):
            summary = c._network_error_summary(error)
            self.assertIn(expected, summary)
            self.assertNotIn('SECRET', summary)

    def test_quake_sampling_announces_request_before_response(self):
        seen = []
        def response(*args, **kwargs):
            self.assertTrue(any('采样' in message and '开始请求' in message for message in seen))
            return self.response({'code': 0, 'data': []})
        with patch.object(c, 'log', side_effect=seen.append), patch.object(c, 'http_post_json', side_effect=response):
            c.search_quake(self.quake_config(adaptive=True))
        self.assertIn('初始化', seen[0])

    def test_quake_filter_counts_explain_zero_additions(self):
        rows = [
            {'ip': '192.*.*.*', 'port': 80},
            {'ip': '192.0.2.1'},
            {'ip': '192.0.2.2', 'port': 80},
            {'ip': '192.0.2.2', 'port': 80}]
        results = []
        counts = c._quake_ingest(rows, results, set())
        self.assertEqual(counts, {'added': 1, 'masked': 1, 'invalid': 1, 'duplicate': 1})
        self.assertEqual(len(results), 1)

    def test_quake_masked_ip_with_hostname_is_retained(self):
        results = []
        counts = c._quake_ingest([{'ip': '192.*.*.*', 'hostname': 'public.example.test', 'port': 443}], results, set())
        self.assertEqual(counts['added'], 1)
        self.assertEqual(results[0]['ip'], '')
        self.assertEqual(len(c.merge_and_dedup(results)), 1)

    def test_quake_refinement_keeps_not_tail_and_parent_expression(self):
        query = '(a OR b) && country:"美国"'
        rows = [{'ip': '192.0.2.1', 'port': 80}, {'ip': '192.0.2.2', 'port': 443}]
        self.assertEqual(c._quake_refine_queries(query, rows), [
            f'({query}) && port:80', f'({query}) && port:443',
            f'({query}) && NOT (port:80 || port:443)'])

    def test_quake_large_partition_refines_without_requesting_offset_1000(self):
        cfg = self.quake_config(interval=0)
        cfg['keys'] = [f'key-{i}' for i in range(30)]
        large = {'code': 0, 'data': [{'ip': '192.0.2.1', 'port': 80,
                  'location': {'country_cn': '美国'}}], 'meta': {'pagination': {'total': 1531}}}
        pages = [self.response(large)] + [self.response({'code': 0, 'data': []})] * 2
        with patch.object(c, 'http_post_json', side_effect=pages) as http:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual(http.call_count, 3)
            self.assertTrue(all(call.args[1]['start'] == 0 for call in http.call_args_list))
            self.assertIn('country:"美国"', http.call_args_list[1].args[1]['query'])
            self.assertIn('NOT (country:"美国")', http.call_args_list[2].args[1]['query'])

    def test_quake_masked_country_reuses_permission_diagnosis(self):
        cfg = self.quake_config(interval=0, partition={'geo': [{'country': '中国', 'provinces': ['北京', '广东']}]})
        cfg['keys'] = ['first', 'second']
        masked = {'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80,
                  'location': {'country_cn': '中国'}}], 'meta': {'pagination': {'total': 1000}}}
        with patch.object(c, 'http_post_json', return_value=self.response(masked)) as http, patch.object(c, 'log') as logger:
            self.assertEqual(c.search_quake(cfg), [])
            self.assertEqual(http.call_count, 2)
            self.assertEqual({call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list}, {'first', 'second'})
            self.assertIn('跳过重复查询', str(logger.call_args_list))

    def test_quake_masked_page_recovers_with_other_key(self):
        cfg = self.quake_config(interval=0, partition={'geo': [{'country': '中国'}]})
        cfg['keys'] = ['masked', 'clear']
        pages = [self.response({'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80,
                    'location': {'country_cn': '中国'}}], 'meta': {'pagination': {'total': 1}}}),
                 self.response({'code': 0, 'data': [{'ip': '192.0.2.1', 'port': 80,
                    'location': {'country_cn': '中国'}}], 'meta': {'pagination': {'total': 1}}})]
        with patch.object(c, 'http_post_json', side_effect=pages) as http, patch.object(c, 'log') as logger:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual([call.args[1]['start'] for call in http.call_args_list], [0, 0])
            self.assertIn('仍有 0 个查询', str(logger.call_args_list))

    def test_quake_request_spacing_covers_phase_and_query_changes(self):
        requester = c._QuakeRequester(3)
        payload = {'start': 0, 'size': 100}
        with patch.object(c.time, 'monotonic', return_value=100), \
             patch.object(c, '_quake_request', return_value=self.response({'code': 0})):
            requester('url', payload, 'a', '#1', '采样', 30)
            requester('url', payload, 'b', '#2', '采集1', 30)
            requester('url', payload, 'c', '#3', '采集2', 30)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [3, 3])

    def test_quake_rate_control_persists_when_switching_keys(self):
        requester = c._QuakeRequester(3)
        with patch.object(c.time, 'monotonic', return_value=100), patch.object(c, '_quake_request', side_effect=[
                self.response({'code': 'q3005', 'message': '请求频繁'}), self.response({'code': 0})]):
            requester('url', {'start': 0, 'size': 100}, 'a', '#1', '采集1', 30)
            requester('url', {'start': 0, 'size': 100}, 'b', '#2', '采集2', 30)
        self.assertEqual(self.sleep.call_args.args[0], 6)

    def test_quake_partition_limit_prevents_unbounded_expansion(self):
        cfg = self.quake_config(interval=0, max_partitions=1)
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 0, 'data': [
                {'ip': '192.0.2.1', 'port': 80}], 'meta': {'pagination': {'total': 1531}}})) as http:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual(http.call_count, 1)

    def cidr_config(self, **extra):
        cfg = self.quake_config()
        cfg.update(cidr=True, run_mode='fixed', ip_versions=[4], interval=0, pageSize=2,
                   state_dir=str(self.root / 'quake_state'))
        cfg.update(extra)
        return cfg

    def quake_page(self, addresses, total):
        return self.response({'code': 0, 'data': [{'ip': ip, 'port': 80} for ip in addresses],
                              'meta': {'pagination': {'total': total}}})

    def test_cidr_is_default_for_existing_all_config(self):
        cfg = self.cidr_config()
        cfg.pop('cidr')
        with patch.object(c, '_search_quake_cidr', return_value=[]) as cidr, \
             patch.object(c, '_search_quake_partitioned') as legacy:
            c.search_quake(cfg)
            cidr.assert_called_once_with(cfg)
            legacy.assert_not_called()

    def test_cidr_binary_split_and_leaf_pagination(self):
        cfg = self.cidr_config(window=3)
        pages = [self.quake_page(['192.0.2.1'], 5),
                 self.quake_page(['10.0.0.1', '10.0.0.2'], 3),
                 self.quake_page(['192.0.2.1', '192.0.2.2'], 2),
                 self.quake_page(['10.0.0.3'], 3)]
        with patch.object(c, 'http_post_json', side_effect=pages) as http:
            result = c.search_quake(cfg)
        self.assertEqual(len(result), 5)
        self.assertEqual([call.args[1]['start'] for call in http.call_args_list], [0, 0, 0, 2])
        queries = [call.args[1]['query'] for call in http.call_args_list]
        self.assertIn('(a OR b) AND ip:"0.0.0.0/0"', queries[0])
        self.assertIn('ip:"0.0.0.0/1"', queries[1])
        self.assertIn('ip:"128.0.0.0/1"', queries[2])
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(state['pending'], [])
        self.assertEqual(state['unresolved'], [])
        self.assertEqual(state['completed'], 2)

    def test_cidr_resume_exact_page_and_completed_cache(self):
        cfg = self.cidr_config()
        with patch.object(c, 'http_post_json', side_effect=[
                self.quake_page(['192.0.2.1', '192.0.2.2'], 3), KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                c.search_quake(cfg)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(state['pending'][-1]['start'], 2)
        with patch.object(c, 'http_post_json', return_value=self.quake_page(['192.0.2.3'], 3)) as http:
            self.assertEqual(len(c.search_quake(cfg)), 3)
            self.assertEqual(http.call_count, 1)
            self.assertEqual(http.call_args.args[1]['start'], 2)
        with patch.object(c, 'http_post_json') as http:
            self.assertEqual(len(c.search_quake(cfg)), 3)
            http.assert_not_called()

    def test_cidr_missing_part_does_not_discard_checkpoint(self):
        cfg = self.cidr_config()
        with patch.object(c, 'http_post_json', return_value=self.quake_page(['192.0.2.1'], 1)):
            c.search_quake(cfg)
        next((self.root / 'quake_state/parts').iterdir()).unlink()
        with self.assertRaises(ValueError):
            c.search_quake(cfg)
        self.assertTrue((self.root / 'quake_state/state.json').exists())

    def test_cidr_query_mismatch_preserves_state(self):
        cfg = self.cidr_config()
        with patch.object(c, 'http_post_json', return_value=self.quake_page([], 0)):
            c.search_quake(cfg)
        path = self.root / 'quake_state/state.json'
        before = path.read_bytes()
        cfg['query'] = 'different'
        with self.assertRaises(ValueError):
            c.search_quake(cfg)
        self.assertEqual(path.read_bytes(), before)

    def test_cidr_default_separately_handles_ipv4_and_ipv6(self):
        cfg = self.cidr_config()
        cfg.pop('ip_versions')
        with patch.object(c, 'http_post_json', side_effect=[self.quake_page([], 0),
                self.quake_page(['2001:db8::1'], 1)]) as http:
            result = c.search_quake(cfg)
        self.assertEqual(len(result), 1)
        self.assertIn('ip:"::/0"', http.call_args_list[1].args[1]['query'])
        self.assertEqual(result[0]['host'], 'http://[2001:db8::1]:80')

    def test_cidr_ipv6_parameter_rejection_is_unresolved(self):
        cfg = self.cidr_config(ip_versions=[6])
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 'q2004', 'message': '参数错误'})):
            c.search_quake(cfg)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(state['completed'], 0)
        self.assertEqual(len(state['unresolved']), 1)

    def test_cidr_single_ip_port_split_has_complement_tail(self):
        node = c._quake_node('192.0.2.1/32')
        children = c._quake_split_node(node, [{'port': 80}, {'port': 443}])
        self.assertEqual([child['port'] for child in children], [80, 443, None])
        self.assertEqual(children[-1]['exclude_ports'], [80, 443])
        tail_query = c._quake_node_query('a OR b', children[-1])
        self.assertIn('AND NOT (port:80 OR port:443)', tail_query)
        next_children = c._quake_split_node(children[-1], [{'port': 8080}])
        self.assertEqual(next_children[-1]['exclude_ports'], [80, 443, 8080])
        self.assertEqual(c._quake_split_node(children[0], [{'port': 80}]), [])

    def test_cidr_network_failure_preserves_pending(self):
        cfg = self.cidr_config(retries=1)
        with patch.object(c, 'http_post_json', return_value=(-1, 'timeout')) as http:
            c.search_quake(cfg)
            self.assertEqual(http.call_count, 2)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(len(state['pending']), 1)
        self.assertEqual(state['pending'][0]['start'], 0)

    def test_cidr_short_page_still_continues_until_total(self):
        cfg = self.cidr_config(pageSize=500)
        with patch.object(c, 'http_post_json', side_effect=[self.quake_page(['192.0.2.1'], 2),
                self.quake_page(['192.0.2.2'], 2)]) as http:
            self.assertEqual(len(c.search_quake(cfg)), 2)
            self.assertEqual(http.call_args_list[1].args[1]['start'], 1)

    def test_cidr_full_masked_first_page_does_not_hide_later_readable_assets(self):
        cfg = self.cidr_config(pageSize=1)
        pages = [self.response({'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80}],
                                'meta': {'pagination': {'total': 2}}}),
                 self.quake_page(['192.0.2.1'], 2)]
        with patch.object(c, 'http_post_json', side_effect=pages):
            self.assertEqual(len(c.search_quake(cfg)), 1)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertTrue(state['unresolved'])

    def test_cidr_invalid_total_never_marks_complete(self):
        cfg = self.cidr_config(retries=0)
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 0, 'data': []})):
            c.search_quake(cfg)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(state['completed'], 0)
        self.assertTrue(state['pending'])

    def test_cidr_partition_budget_retains_unresolved_root(self):
        cfg = self.cidr_config(window=1, max_partitions=1)
        with patch.object(c, 'http_post_json', return_value=self.quake_page(['192.0.2.1'], 1531)) as http:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual(http.call_count, 1)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertTrue(state['unresolved'])

    def test_cidr_quota_key_switches_same_offset(self):
        cfg = self.cidr_config(keys=['empty', 'working'])
        with patch.object(c, 'http_post_json', side_effect=[
                self.response({'code': 'q2002', 'message': '积分不足'}), self.quake_page([], 0)]) as http:
            c.search_quake(cfg)
            self.assertEqual([call.args[1]['start'] for call in http.call_args_list], [0, 0])
            self.assertEqual([call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list], ['empty', 'working'])

    def test_cidr_single_ip_port_fallback_end_to_end(self):
        cfg = self.cidr_config(window=1)
        directory, path, state = c._quake_open_state(cfg)
        state['pending'] = [c._quake_node('192.0.2.1/32')]
        c._atomic_write_json(path, state)
        def page(port, total):
            return self.response({'code': 0, 'data': [{'ip': '192.0.2.1', 'port': port}],
                                  'meta': {'pagination': {'total': total}}})
        with patch.object(c, 'http_post_json', side_effect=[page(80, 2), page(80, 1), page(443, 1)]) as http:
            self.assertEqual(len(c.search_quake(cfg)), 2)
        self.assertIn('AND port:80', http.call_args_list[1].args[1]['query'])
        self.assertIn('AND NOT (port:80)', http.call_args_list[2].args[1]['query'])
        self.assertEqual(json.loads(Path(path).read_text())['unresolved'], [])

    def test_cidr_single_ip_single_port_overflow_is_unresolved(self):
        cfg = self.cidr_config(window=1)
        directory, path, state = c._quake_open_state(cfg)
        state['pending'] = [c._quake_node('192.0.2.1/32', port=80)]
        c._atomic_write_json(path, state)
        with patch.object(c, 'http_post_json', return_value=self.quake_page(['192.0.2.1'], 2)) as http:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual(http.call_count, 1)
        state = json.loads(Path(path).read_text())
        self.assertTrue(state['unresolved'])
        self.assertEqual(state['completed'], 0)

    def test_cidr_masked_task_retried_with_new_key_on_next_run(self):
        cfg = self.cidr_config()
        with patch.object(c, 'http_post_json', return_value=self.response({'code': 0, 'data': [
                {'ip': '192.*.*.*', 'port': 80}], 'meta': {'pagination': {'total': 1}}})):
            self.assertEqual(c.search_quake(cfg), [])
        state_path = self.root / 'quake_state/state.json'
        self.assertEqual(json.loads(state_path.read_text())['completed'], 0)
        cfg['keys'] = ['new-key']
        with patch.object(c, 'http_post_json', return_value=self.quake_page(['192.0.2.1'], 1)) as http:
            self.assertEqual(len(c.search_quake(cfg)), 1)
            self.assertEqual(http.call_args.kwargs['headers']['X-QuakeToken'], 'new-key')
        state = json.loads(state_path.read_text())
        self.assertEqual(state['unresolved'], [])
        self.assertEqual(state['completed'], 1)

    def test_cidr_nonempty_directory_without_manifest_is_preserved(self):
        cfg = self.cidr_config()
        directory = Path(cfg['state_dir'])
        directory.mkdir()
        (directory / 'important').write_text('keep')
        with self.assertRaises(ValueError):
            c.search_quake(cfg)
        self.assertEqual((directory / 'important').read_text(), 'keep')

    def test_cidr_first_page_limit_does_not_expand_without_total(self):
        cfg = self.cidr_config(pageSize=500, retries=2)
        with patch.object(c, 'http_post_json', return_value=self.response({
                'code': 'q2001', 'message': '最大允许条数限制'})) as http:
            c.search_quake(cfg)
            self.assertEqual(http.call_count, 3)
            self.assertEqual([call.args[1]['size'] for call in http.call_args_list], [500, 250, 125])
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(state['created'], 1)
        self.assertEqual(len(state['unresolved']), 1)

    def test_cidr_port_hints_survive_resume(self):
        node = c._quake_node('192.0.2.1/32')
        node['port_hints'] = [80, 443]
        children = c._quake_split_node(node, [])
        self.assertEqual([child['port'] for child in children], [80, 443, None])

    def test_cidr_timeout_page_floor_and_recovery(self):
        cfg = self.cidr_config(pageSize=500, retries=5)
        client = c._QuakeClient(cfg)
        timeout = (-1, 'timeout')
        ok = self.quake_page(['192.0.2.1'], 1)
        with patch.object(c, 'http_post_json', side_effect=[timeout] * 5 + [ok, ok, ok, ok, ok, ok]) as http:
            for _ in range(6):
                client.fetch('test', 0, 500, 'test')
        sizes = [call.args[1]['size'] for call in http.call_args_list]
        self.assertEqual(min(sizes), 50)
        self.assertEqual(client.page_size, 400)
        self.assertGreater(sizes[-1], 50)

    def test_cidr_internal_masked_node_splits_without_probing_all_keys(self):
        cfg = self.cidr_config(window=1, max_partitions=1, keys=[f'k{i}' for i in range(30)])
        masked = self.response({'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80}],
                                'meta': {'pagination': {'total': 1531}}})
        with patch.object(c, 'http_post_json', return_value=masked) as http:
            c.search_quake(cfg)
            self.assertEqual(http.call_count, 1)

    def test_cidr_masked_leaf_has_bounded_probes_and_one_retry_scope(self):
        cfg = self.cidr_config(keys=[f'k{i}' for i in range(30)], pageSize=1)
        masked = self.response({'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80}],
                                'meta': {'pagination': {'total': 2}}})
        with patch.object(c, 'http_post_json', return_value=masked) as http:
            c.search_quake(cfg)
            self.assertEqual(http.call_count, 6)
        state = json.loads((self.root / 'quake_state/state.json').read_text())
        self.assertEqual(len(state['unresolved']), 1)
        self.assertEqual(state['unresolved'][0]['node']['start'], 0)

    def test_cidr_overlapping_legacy_retries_coalesce_to_one_scope(self):
        tasks = []
        for start in [282, 0, 31, 62, 77, 92]:
            node = c._quake_node('0.0.0.0/3')
            node['start'] = start
            tasks.append(node)
        merged = c._quake_coalesce_tasks(tasks)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['start'], 0)

    def test_cidr_next_run_tries_further_keys_after_mask_probe_budget(self):
        cfg = self.cidr_config(keys=[f'k{i}' for i in range(10)])
        masked = self.response({'code': 0, 'data': [{'ip': '120.*.*.*', 'port': 80}],
                                'meta': {'pagination': {'total': 1}}})
        with patch.object(c, 'http_post_json', return_value=masked) as http:
            c.search_quake(cfg)
            first_keys = {call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list}
        with patch.object(c, 'http_post_json', return_value=masked) as http:
            c.search_quake(cfg)
            second_keys = {call.kwargs['headers']['X-QuakeToken'] for call in http.call_args_list}
        self.assertFalse(first_keys & second_keys)

    def test_cidr_live_snapshot_written_before_interrupt(self):
        cfg = self.cidr_config(pageSize=1)
        with patch.object(c, 'http_post_json', side_effect=[self.quake_page(['192.0.2.1'], 2), KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                c.search_quake(cfg)
        snapshot = self.root / 'quake_state/quake_urls.txt'
        self.assertEqual(snapshot.read_text().splitlines(), ['http://192.0.2.1:80'])


if __name__ == '__main__':
    unittest.main()
