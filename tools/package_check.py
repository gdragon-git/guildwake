"""Build/inspect artifacts and smoke safe CLI. No download or host installation."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def source_files():
    for directory, folders, files in os.walk(ROOT):
        folders[:] = [name for name in folders if name not in {'.git', '.venv', '__pycache__', 'build', 'dist'}
                      and not name.endswith('.egg-info')]
        for name in files:
            if not name.endswith('.pyc'):
                yield Path(directory) / name


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def allowed(name):
    parts = PurePosixPath(name).parts
    return not (PurePosixPath(name).is_absolute() or '..' in parts or
                any(p in {'.venv', '__pycache__', 'work', 'outputs', 'credentials'} for p in parts)
                or name.endswith(('.pyc', '.sqlite', '.db', '.key', '.log')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.is_relative_to(ROOT):
        parser.exit(2, 'Use a new output directory outside the source tree.\n')
    output.mkdir(parents=True)
    before = {p.relative_to(ROOT).as_posix(): digest(p) for p in source_files()}
    log = io.StringIO()
    try:
        import setuptools.build_meta as backend
        with tempfile.TemporaryDirectory(prefix='guildwake-package-') as temporary:
            temp = Path(temporary)
            source = temp / 'source'
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '.venv', '__pycache__', 'build', 'dist', '*.egg-info'))
            previous = Path.cwd()
            try:
                os.chdir(source)
                with redirect_stdout(log), redirect_stderr(log):
                    wheel = backend.build_wheel(str(output))
                    sdist = backend.build_sdist(str(output))
            finally:
                os.chdir(previous)
            with zipfile.ZipFile(output / wheel) as archive:
                names = archive.namelist()
                assert all(allowed(name) for name in names), 'wheel_payload'
                assert 'discord_amp/config.py' in names and 'discord_amp/runtime.py' in names
                assert sum('/templates/' in name for name in names) == 6, 'template_payload'
                metadata = next(name for name in names if name.endswith('.dist-info/METADATA'))
                text = archive.read(metadata).decode()
                assert 'License-Expression: Apache-2.0' in text and 'Name: guildwake' in text
                assert any(name.endswith('/licenses/LICENSE') for name in names)
                assert sum('/THIRD_PARTY_LICENSES/' in name for name in names) == 14
                unpacked = temp / 'wheel'
                archive.extractall(unpacked)
            with tarfile.open(output / sdist, 'r:gz') as archive:
                members = archive.getmembers()
                assert all(allowed(m.name) and (m.isfile() or m.isdir()) for m in members), 'sdist_payload'
                assert any(m.name.endswith('/examples/profile.example.json') for m in members)
                assert any(m.name.endswith('/tests/test_configuration.py') for m in members)
            smoke = []
            for action in ('check', 'doctor', 'render'):
                code = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('discord_amp.runtime',run_name='__main__')"
                command = [sys.executable, '-I', '-B', '-c', code, str(unpacked), action,
                           '--config', str(ROOT / 'examples/profile.example.json')]
                if action == 'render':
                    command += ['--output', str(temp / 'rendered')]
                result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                assert result.returncode == 0, action + ':' + result.stderr
                value = json.loads(result.stdout)
                assert value.get('mutations', 0) == 0 and value.get('network_probes', 0) == 0
                smoke.append({'command': action, 'passed': True})
        assert before == {p.relative_to(ROOT).as_posix(): digest(p) for p in source_files()}, 'source_changed'
        report = {'passed': True, 'artifacts': {name: {'bytes': (output / name).stat().st_size,
            'sha256': digest(output / name)} for name in (wheel, sdist)},
            'cli_smoke': smoke, 'source_unchanged': True, 'downloads': 0,
            'services_started': False, 'independent_installation_qualified': False,
            'proof': 'local build/payload and isolated unpacked-wheel CLI; no clean Linux install'}
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report))
    finally:
        (output / 'build.log').write_text(log.getvalue(), encoding='utf-8')


if __name__ == '__main__':
    main()
