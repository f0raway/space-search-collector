import contextlib
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import collector_runs as runs
import space_search_collector as c


class RunManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        c.COLLECT_SINK.clear()
        c._CURRENT_MODULE = None
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(c.time, 'sleep'))

    def cfg(self, **extra):
        cfg = dict(url='https://example.test', email='test@example.test', token='SECRET',
                   query='a OR b', interval=0, state_dir=str(self.root / 'runs'))
        cfg.update(extra)
        return cfg

    def row(self, host='https://example.test/path?q=1'):
        return c._fofa_parse_row([host, '192.0.2.1', 443, 'https', 'title',
                                  'country', 'province', 'city', 'domain.test', host])

    def identity(self):
        cfg = self.cfg()
        return dict(query=cfg['query'], url=cfg['url'], email=cfg['email'], full=False)

    def directories(self):
        return sorted(path for path in (self.root / 'runs').iterdir() if path.is_dir() and path.name != 'parts')

    def state(self, completed=0, requests=0):
        return dict(base_query='a OR b', pending=[[0, 0]], completed=[{'status': 'empty'}] * completed,
                    requests=requests, full=False, limit=10000)

    def test_completed_run_creates_fresh_directory_next_time(self):
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)) as api:
            c.search_fofa(self.cfg())
            c.search_fofa(self.cfg())
            self.assertEqual(api.call_count, 2)
        self.assertEqual(len(self.directories()), 2)
        for directory in self.directories():
            self.assertEqual(json.loads((directory / 'run.json').read_text())['status'], 'complete')
            self.assertTrue((directory / 'fofa_merged.csv').exists())

    def test_failed_run_resumes_same_directory(self):
        with patch.object(c, '_fofa_query', side_effect=c.FofaRequestError('quota', 1)):
            with self.assertRaises(c.FofaRequestError):
                c.search_fofa(self.cfg())
        directory = self.directories()[0]
        self.assertEqual(json.loads((directory / 'run.json').read_text())['status'], 'failed')
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)):
            c.search_fofa(self.cfg())
        self.assertEqual(self.directories(), [directory])
        self.assertEqual(json.loads((directory / 'state.json').read_text())['requests'], 2)

    def test_auto_resume_chooses_furthest_progress_and_disables_older(self):
        parent = self.root / 'runs'
        for name, completed in [('newer', 1), ('older_more_progress', 3)]:
            directory = parent / name
            directory.mkdir(parents=True)
            runs.atomic_write_json(directory / 'state.json', self.state(completed))
        with runs.managed_run('fofa', parent, self.identity(), logger=lambda _: None) as run:
            self.assertEqual(Path(run.directory).name, 'older_more_progress')
        metadata = json.loads((parent / 'newer/run.json').read_text())
        self.assertFalse(metadata['auto_resume'])
        self.assertTrue((parent / 'newer/state.json').exists())

    def test_new_run_disables_unfinished_candidate_without_deleting_it(self):
        parent = self.root / 'runs'
        previous = parent / 'previous'
        previous.mkdir(parents=True)
        path = previous / 'state.json'
        runs.atomic_write_json(path, self.state())
        before = path.read_bytes()
        with runs.managed_run('fofa', parent, self.identity(), new=True, logger=lambda _: None) as run:
            selected = run.directory
            self.assertNotEqual(selected, str(previous))
        self.assertEqual(path.read_bytes(), before)
        with runs.managed_run('fofa', parent, self.identity(), logger=lambda _: None) as run:
            self.assertEqual(run.directory, selected)

    def test_explicit_resume_rejects_mismatch_without_changing_state(self):
        previous = self.root / 'previous'
        previous.mkdir()
        state = self.state()
        state['base_query'] = 'other'
        runs.atomic_write_json(previous / 'state.json', state)
        before = (previous / 'state.json').read_bytes()
        with self.assertRaises(ValueError):
            with runs.managed_run('fofa', self.root / 'runs', self.identity(), resume=previous):
                self.fail('should reject')
        self.assertEqual((previous / 'state.json').read_bytes(), before)

    def test_old_fixed_layout_checkpoint_can_resume_without_moving_files(self):
        cfg = self.cfg(run_mode='fixed')
        with patch.object(c, '_fofa_query', side_effect=c.FofaRequestError('quota', 1)):
            with self.assertRaises(c.FofaRequestError):
                c.search_fofa(cfg)
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)):
            c.search_fofa(self.cfg())
        self.assertEqual(self.directories(), [])
        self.assertTrue((self.root / 'runs/fofa_merged.csv').exists())
        self.assertTrue((self.root / 'runs/state.json').exists())

    def test_csv_merge_failure_resumes_without_api_calls(self):
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)), \
             patch.object(c, '_fofa_merge_parts', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                c.search_fofa(self.cfg())
        with patch.object(c, '_fofa_query') as api:
            self.assertEqual(len(c.search_fofa(self.cfg())), 1)
            api.assert_not_called()
        self.assertEqual(len(self.directories()), 1)
        self.assertTrue((self.directories()[0] / 'fofa_merged.csv').exists())

    def test_full_native_csv_preserves_location_domain_and_link(self):
        with patch.object(c, '_fofa_query', return_value=([self.row()], 1, 1)):
            c.search_fofa(self.cfg())
        with (self.directories()[0] / 'fofa_merged.csv').open(newline='') as file:
            reader = csv.DictReader(file)
            row = next(reader)
            self.assertEqual(reader.fieldnames, c.FOFA_PART_FIELDS)
        self.assertEqual(row['country'], 'country')
        self.assertEqual(row['region'], 'province')
        self.assertEqual(row['city'], 'city')
        self.assertEqual(row['domain'], 'domain.test')
        self.assertEqual(row['link'], 'https://example.test/path?q=1')

    def test_csv_preserves_rows_that_cannot_be_exported_as_urls(self):
        row = self.row()
        row.update(link='', host='', ip='', port=None)
        with patch.object(c, '_fofa_query', return_value=([row], 1, 1)):
            self.assertEqual(c.search_fofa(self.cfg()), [])
        with (self.directories()[0] / 'fofa_merged.csv').open(newline='') as file:
            self.assertEqual(len(list(csv.DictReader(file))), 1)

    def test_fofa_timeout_fields_and_full_are_passed_to_api(self):
        with patch.object(c, 'http_get', return_value=(200, '{"results": [], "size": 0}')) as http:
            c.fofa_fetch(self.cfg(timeout=7), 'query', full=True)
            self.assertEqual(http.call_args.kwargs['timeout'], 7)
            self.assertEqual(http.call_args.kwargs['params']['fields'], c.FOFA_FIELDS)
            self.assertEqual(http.call_args.kwargs['params']['full'], 'true')

    def test_api_error_does_not_echo_credentials(self):
        cfg = self.cfg()
        with patch.object(c, 'http_get', return_value=(200, json.dumps({
                'error': True, 'errmsg': 'bad SECRET test@example.test'}))):
            _, _, error = c.fofa_fetch(cfg, 'query')
        self.assertNotIn('SECRET', error)
        self.assertNotIn('test@example.test', error)

    def test_source_lock_blocks_second_writer_and_releases(self):
        cfg = self.cfg(run_mode='fixed')
        directory = Path(cfg['state_dir'])
        directory.mkdir()
        with runs.exclusive_lock(directory / '.run.lock'), patch.object(c, '_fofa_query') as api:
            with self.assertRaises(ValueError):
                c.search_fofa(cfg)
            api.assert_not_called()
        with patch.object(c, '_fofa_query', return_value=([], 0, 1)):
            c.search_fofa(cfg)

    def test_os_lock_blocks_a_second_process(self):
        path = self.root / 'test.lock'
        script = "from collector_runs import exclusive_lock\nimport sys\ntry:\n with exclusive_lock(sys.argv[1]): pass\nexcept ValueError:\n sys.exit(7)\n"
        with runs.exclusive_lock(path):
            result = subprocess.run([sys.executable, '-c', script, str(path)],
                                    cwd=Path(c.__file__).parent, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 7)

    def test_output_lock_prevents_any_engine_calls(self):
        output, logfile = self.root / 'out', self.root / 'log'
        config = {'module': {'hunter': {'query': 'test', 'url': 'url', 'keys': ['key']}}}
        with runs.exclusive_lock(str(output) + '.lock'), patch.object(c, 'http_get') as api:
            with self.assertRaises(ValueError):
                c.run_collect(config, output, logfile)
            api.assert_not_called()

    def test_csv_merge_failure_does_not_truncate_previous_csv(self):
        directory = self.root
        (directory / 'fofa_merged.csv').write_text('previous')
        (directory / 'bad.csv').write_text('bad_header\nvalue\n')
        with self.assertRaises(ValueError):
            c._fofa_merge_parts({'completed': [{'status': 'saved', 'file': 'bad.csv'}]}, str(directory))
        self.assertEqual((directory / 'fofa_merged.csv').read_text(), 'previous')

    def test_fofa_query_change_creates_isolated_new_run(self):
        with patch.object(c, '_fofa_query', return_value=([self.row('https://one.test')], 1, 1)):
            c.search_fofa(self.cfg())
        with patch.object(c, '_fofa_query', return_value=([self.row('https://two.test')], 1, 1)):
            result = c.search_fofa(self.cfg(query='different'))
        self.assertEqual(len(self.directories()), 2)
        self.assertEqual([asset['host'] for asset in result], ['https://two.test'])

    def test_cli_new_query_and_explicit_resume_options(self):
        cases = [(['-s', 'fofa', '--new', '-q', 'query'], {'new_run': True, 'query': 'query'}),
                 (['-s', 'fofa', '--resume', '/tmp/run'], {'resume_dir': '/tmp/run'})]
        for args, expected in cases:
            with self.subTest(args=args), patch('sys.argv', ['collector'] + args), \
                 patch.object(c, 'ensure_config', return_value=True), patch.object(c, 'load_config', return_value={}), \
                 patch.object(c, 'run_collect', return_value=[{}]) as run:
                self.assertEqual(c.main(), 0)
                for key, value in expected.items():
                    self.assertEqual(run.call_args.kwargs[key], value)

    def test_query_override_is_scoped_and_does_not_modify_config(self):
        config = {'module': {'hunter': {'query': 'old', 'url': 'url', 'keys': ['key']}}}
        handler = unittest.mock.Mock(return_value=[])
        with patch.dict(c.MODULE_HANDLERS, hunter=handler):
            c.run_collect(config, self.root / 'out', self.root / 'log', query='new')
        self.assertEqual(handler.call_args.args[0]['query'], 'new')
        self.assertEqual(config['module']['hunter']['query'], 'old')

    def test_ambiguous_query_override_rejected_before_requests(self):
        with self.assertRaises(ValueError), patch.object(c, 'http_get') as api:
            c.run_collect({'module': {'fofa': {}, 'hunter': {}}}, query='test')
        api.assert_not_called()

    def test_quake_uses_same_run_lifecycle_and_resumes_exact_offset(self):
        cfg = dict(url='https://example.test', query='query', keys=['key'], interval=0,
                   ip_versions=[4], pageSize=1, state_dir=str(self.root / 'runs'))
        def page(ip):
            return 200, json.dumps({'code': 0, 'data': [{'ip': ip, 'port': 80}],
                                    'meta': {'pagination': {'total': 2}}})
        with patch.object(c, 'http_post_json', side_effect=[page('192.0.2.1'), KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                c.search_quake(cfg)
        directory = self.directories()[0]
        with patch.object(c, 'http_post_json', return_value=page('192.0.2.2')) as api:
            self.assertEqual(len(c.search_quake(cfg)), 2)
            self.assertEqual(api.call_args.args[1]['start'], 1)
        self.assertEqual(self.directories(), [directory])
        self.assertEqual(json.loads((directory / 'run.json').read_text())['status'], 'complete')
        with patch.object(c, 'http_post_json', return_value=(200, '{"code":0,"data":[],"meta":{"pagination":{"total":0}}}')) as api:
            c.search_quake(cfg)
            self.assertEqual(api.call_count, 1)
        self.assertEqual(len(self.directories()), 2)

    def test_embedded_concurrent_runs_keep_partial_results_separate(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        barrier = Barrier(2)
        def handler(cfg):
            partial = c._module_results()
            barrier.wait(timeout=3)
            partial.append({'host': 'https://' + cfg['query'] + '.test', 'source': 'hunter'})
            barrier.wait(timeout=3)
            return partial
        def collect(name):
            cfg = {'module': {'hunter': {'url': 'url', 'query': name}}}
            return c.run_collect(cfg, self.root / (name + '.out'), self.root / (name + '.log'))
        with patch.dict(c.MODULE_HANDLERS, hunter=handler), ThreadPoolExecutor(max_workers=2) as executor:
            first, second = [executor.submit(collect, name) for name in ('one', 'two')]
            self.assertEqual([item['host'] for item in first.result(timeout=5)], ['one.test'])
            self.assertEqual([item['host'] for item in second.result(timeout=5)], ['two.test'])

    def test_api_accepts_numeric_string_total_and_default_url(self):
        cfg = self.cfg()
        cfg.pop('url')
        with patch.object(c, 'http_get', return_value=(200, '{"results": [], "size": "0"}')) as http:
            self.assertEqual(c.fofa_fetch(cfg, 'query'), ([], 0, None))
            self.assertEqual(http.call_args.args[0], 'https://fofa.info/api/v1/search/all')

    def test_fofa_checkpoint_does_not_read_paths_outside_run(self):
        directory = self.root / 'fixed'
        directory.mkdir()
        state = self.state()
        state['completed'] = [{'status': 'saved', 'file': '../outside.csv'}]
        runs.atomic_write_json(directory / 'state.json', state)
        with self.assertRaises(ValueError), patch.object(c, '_fofa_query') as api:
            c.search_fofa(self.cfg(run_mode='fixed', state_dir=str(directory)))
        api.assert_not_called()
        self.assertTrue((directory / 'state.json').exists())


if __name__ == '__main__':
    unittest.main()
