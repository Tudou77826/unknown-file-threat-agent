from __future__ import annotations

from typing import Protocol

from ...contracts import (
    ActivityQueryResult,
    AssetActivityQuery,
    ExtensionActivityQuery,
    FileActivityQuery,
    NetworkActivityQuery,
    PackageActivityQuery,
    ProcessActivityQuery,
    ServiceActivityQuery,
    SocketActivityQuery,
)


class ProcessActivityQueryPort(Protocol):
    def query_process(self, query: ProcessActivityQuery) -> ActivityQueryResult: ...


class NetworkActivityQueryPort(Protocol):
    def query_network(self, query: NetworkActivityQuery) -> ActivityQueryResult: ...


class SocketActivityQueryPort(Protocol):
    def query_socket(self, query: SocketActivityQuery) -> ActivityQueryResult: ...


class FileActivityQueryPort(Protocol):
    def query_file(self, query: FileActivityQuery) -> ActivityQueryResult: ...


class ServiceActivityQueryPort(Protocol):
    def query_service(self, query: ServiceActivityQuery) -> ActivityQueryResult: ...


class PackageActivityQueryPort(Protocol):
    def query_package(self, query: PackageActivityQuery) -> ActivityQueryResult: ...


class AssetActivityQueryPort(Protocol):
    def query_asset(self, query: AssetActivityQuery) -> ActivityQueryResult: ...


class ExtensionActivityQueryPort(Protocol):
    def query_extension(self, query: ExtensionActivityQuery) -> ActivityQueryResult: ...
