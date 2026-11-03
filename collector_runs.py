"""Shared run selection, atomic storage and process locks; independent of search APIs."""

import json
import os
import tempfile
from contextlib import contextmanager, ExitStack
from datetime import datetime


@contextmanager
def atomic_text_file(path, newline=None):
    path = os.path.abspath(os.fspath(path))
    fd, temporary = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.tmp',
                                     dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline=newline) as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_json(path, data):
    with atomic_text_file(path) as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


@contextmanager
def exclusive_lock(path):
    """Nonblocking OS lock. Keep sidecar files in place to avoid inode races."""
    file = open(path, 'a+', encoding='utf-8')
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(file.fileno()).st_size == 0:
                file.write(' ')
                file.flush()
            file.seek(0)
            try:
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise ValueError(f'文件或任务正在被其他进程使用: {path}') from exc
        else:
            import fcntl
            try:
                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError(f'文件或任务正在被其他进程使用: {path}') from exc
        locked = True
        yield
    finally:
        if locked and os.name == 'nt':
            file.seek(0)
            msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
        file.close()


def read_json(path):
    with open(path, encoding='utf-8') as file:
        return json.load(file)


def _state_matches(source, identity, state):
    if source == 'fofa':
        return (state.get('base_query') == identity['query']
                and state.get('full', False) == identity['full']
                and state.get('url', identity['url']) == identity['url']
                and state.get('email', identity['email']) == identity['email'])
    return state.get('identity') == identity


def _state_progress(state):
    completed = state.get('completed', [])
    return len(completed) if isinstance(completed, list) else int(completed)


def run_status(source, state):
    if state.get('pending') or state.get('unresolved'):
        return 'incomplete'
    if source == 'fofa':
        if any(record.get('status') == 'cannot_split' or
               (record.get('total', 0) > 10000 and record.get('rows', 0) < record['total'])
               for record in state.get('completed', [])):
            return 'partial'
        if not state.get('merged'):
            return 'incomplete'
    return 'complete'


class Run:
    def __init__(self, directory, metadata):
        self.directory = directory
        self.metadata = metadata

    def update(self, status):
        self.metadata['status'] = status
        self.metadata['updated_at'] = datetime.now().isoformat(timespec='seconds')
        atomic_write_json(os.path.join(self.directory, 'run.json'), self.metadata)


def _candidate(directory, source, identity):
    state_path = os.path.join(directory, 'state.json')
    metadata_path = os.path.join(directory, 'run.json')
    metadata = read_json(metadata_path) if os.path.isfile(metadata_path) else None
    if metadata and (metadata.get('source') != source or metadata.get('identity') != identity
                     or not metadata.get('auto_resume', True)
                     or metadata.get('status') in ('complete', 'partial', 'superseded')):
        return None
    if not os.path.isfile(state_path):
        # A process may have exited after run creation, before writing its first state.
        return ((0, 0, directory), directory) if metadata else None
    state = read_json(state_path)
    if not _state_matches(source, identity, state):
        return None
    if not state.get('auto_resume', True) and state.get('pending'):
        return None
    if run_status(source, state) in ('complete', 'partial'):
        return None
    return ((_state_progress(state), int(state.get('requests', 0)), directory), directory)


@contextmanager
def managed_run(source, parent, identity, new=False, resume=None, logger=print):
    """Resume the furthest matching unfinished run, otherwise create a timestamped run.

    Accepts old fixed-layout checkpoints in parent itself without moving user data.
    Metadata and locks live beside the checkpoint, never contain API credentials.
    """
    parent = os.path.abspath(os.fspath(parent))
    os.makedirs(parent, exist_ok=True)
    with ExitStack() as held:
        with exclusive_lock(os.path.join(parent, '.manager.lock')):
            candidates = []
            directories = [parent] + [entry.path for entry in os.scandir(parent)
                                       if entry.is_dir(follow_symlinks=False) and entry.name != 'parts']
            for directory in directories:
                try:
                    candidate = _candidate(directory, source, identity)
                    if candidate:
                        candidates.append(candidate)
                except (OSError, ValueError, TypeError, KeyError, AttributeError):
                    logger(f'[{source.upper()}] 无法自动读取旧断点, 已保留: {directory}')
            candidates.sort(reverse=True)
            if resume:
                directory = os.path.abspath(os.fspath(resume))
                state_path = os.path.join(directory, 'state.json')
                if not os.path.isfile(state_path) or not _state_matches(source, identity, read_json(state_path)):
                    raise ValueError('指定恢复目录缺少 state.json 或与查询/账号/范围不匹配')
                mode = '显式恢复'
            elif candidates and not new:
                directory = candidates[0][1]
                mode = '自动恢复进度最多的未完成任务'
            else:
                directory = tempfile.mkdtemp(prefix=datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '_', dir=parent)
                mode = '创建新任务'
            held.enter_context(exclusive_lock(os.path.join(directory, '.run.lock')))
            metadata = {'version': 1, 'source': source, 'identity': identity,
                        'auto_resume': True, 'status': 'running'}
            run = Run(directory, metadata)
            run.update('running')
            # Disable old matching candidates via sidecars, without modifying or deleting their state.
            for _, older in ([] if resume else candidates):
                if os.path.realpath(older) == os.path.realpath(directory):
                    continue
                try:
                    with exclusive_lock(os.path.join(older, '.run.lock')):
                        old = read_json(os.path.join(older, 'run.json')) if os.path.isfile(os.path.join(older, 'run.json')) else dict(metadata)
                        old.update(auto_resume=False, status='superseded', superseded_by=directory)
                        atomic_write_json(os.path.join(older, 'run.json'), old)
                except (OSError, ValueError):
                    logger(f'[{source.upper()}] 旧任务正在使用或无法更新, 保留原状: {older}')
        logger(f'[{source.upper()}] {mode}: {directory}')
        try:
            yield run
        except KeyboardInterrupt:
            run.update('interrupted')
            raise
        except BaseException:
            run.update('failed')
            raise
        else:
            state_path = os.path.join(directory, 'state.json')
            status = run_status(source, read_json(state_path)) if os.path.isfile(state_path) else 'incomplete'
            run.update(status)
            logger(f'[{source.upper()}] 任务状态: {status}; 运行目录: {directory}')
