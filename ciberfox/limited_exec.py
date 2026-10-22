"""Lanzador POSIX con límites; NO reemplaza un sandbox de SO sin red."""
import os
import resource
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2, 32 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    command = sys.argv[1:]
    if not command or not os.path.isabs(command[0]):
        raise SystemExit("Ejecutable absoluto requerido")
    os.execve(command[0], command, dict(os.environ))


if __name__ == "__main__":
    main()
