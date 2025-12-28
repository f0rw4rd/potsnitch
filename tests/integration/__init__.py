"""PotSnitch integration tests.

This package contains integration tests that verify honeypot detection
against real honeypot containers running via Docker.

To run tests:
    pytest tests/integration/ -v

To run only fast tests (no Docker required):
    pytest tests/integration/ -v -m "not slow"

To run Docker-based tests:
    pytest tests/integration/ -v -m "docker"

Prerequisites:
    - Docker and docker-compose must be installed
    - Run: docker-compose -f tests/docker/docker-compose.yml up -d
"""
