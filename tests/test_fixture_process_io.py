import subprocess
import sys
import time
import unittest

from fixtures.process_io import read_line


class ProcessBarrierTest(unittest.TestCase):
    def child(self, code):
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        self.addCleanup(cleanup)
        return child

    def test_actual_pipe_retains_each_barrier_without_prefetch(self):
        child = self.child("import os; os.write(1, b'first\\nsecond\\n')")
        self.assertEqual(read_line(child.stdout), b"first\n")
        self.assertEqual(read_line(child.stdout), b"second\n")
        with self.assertRaises(EOFError):
            read_line(child.stdout)

    def test_partial_barrier_deadline_is_bounded(self):
        child = self.child("import os; os.write(1,b'partial'); os.read(0,1)")
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            read_line(child.stdout, timeout=0.2)
        self.assertLess(time.monotonic() - started, 2)

    def test_barrier_limit_does_not_drain_excess(self):
        child = self.child("import os; os.write(1,b'abcd\\n'); os.read(0,1)")
        with self.assertRaises(ValueError):
            read_line(child.stdout, maximum=3)
        self.assertEqual(read_line(child.stdout), b"d\n")
