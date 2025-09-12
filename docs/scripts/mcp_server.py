#!/usr/bin/env python3
"""
CellFrame SDK MCP Server - Model Context Protocol Server для CellFrame SDK

Этот сервер предоставляет инструменты для анализа и работы с CellFrame SDK
через Model Context Protocol для интеграции с AI-системами.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import asyncio
import logging
from dataclasses import dataclass
from enum import Enum

# MCP SDK imports
try:
    from mcp.server import Server
    from mcp.types import (
        Resource,
        Tool,
        TextContent,
        ImageContent,
        EmbeddedResource,
        LoggingLevel
    )
    import mcp.server.stdio
except ImportError:
    print("Ошибка: MCP SDK не установлен. Установите: pip install mcp")
    sys.exit(1)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cellframe-mcp-server")

@dataclass
class CellFrameSDKContext:
    """Контекст CellFrame SDK проекта"""
    root_path: Path
    chain_modules: List[str]
    service_modules: List[str]
    consensus_modules: List[str]

    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.chain_modules = [
            "chain", "common", "compose", "wallet", "mempool"
        ]
        self.service_modules = [
            "app", "app-db", "datum", "vpn", "xchange", "stake", "voting", "bridge"
        ]
        self.consensus_modules = [
            "dag-poa", "dag-pos", "esbocs", "block-pow", "none"
        ]

class CellFrameMCPTools:
    """Инструменты для работы с CellFrame SDK через MCP"""

    def __init__(self, context: CellFrameSDKContext):
        self.context = context

    async def analyze_chain_modules(self) -> Dict[str, Any]:
        """Анализ модулей блокчейн цепочки CellFrame SDK"""
        chain_info = {}

        modules_path = self.context.root_path / "modules"
        if modules_path.exists():
            for module in self.chain_modules:
                module_path = modules_path / module
                if module_path.exists():
                    files = list(module_path.glob("*.c"))
                    headers = list(module_path.glob("*.h"))
                    chain_info[module] = {
                        "files": len(files),
                        "headers": len(headers),
                        "path": str(module_path),
                        "status": "implemented"
                    }
                else:
                    chain_info[module] = {
                        "status": "not_found",
                        "path": str(module_path)
                    }

        return chain_info

    async def analyze_service_modules(self) -> Dict[str, Any]:
        """Анализ сервисных модулей CellFrame SDK"""
        service_info = {}

        modules_path = self.context.root_path / "modules"
        if modules_path.exists():
            for service in self.service_modules:
                service_path = modules_path / "service" / service
                if service_path.exists():
                    files = list(service_path.glob("*.c"))
                    headers = list(service_path.glob("*.h"))
                    service_info[service] = {
                        "files": len(files),
                        "headers": len(headers),
                        "path": str(service_path),
                        "status": "implemented"
                    }
                else:
                    service_info[service] = {
                        "status": "not_found",
                        "path": str(service_path)
                    }

        return service_info

    async def analyze_consensus_algorithms(self) -> Dict[str, Any]:
        """Анализ алгоритмов консенсуса CellFrame SDK"""
        consensus_info = {}

        consensus_path = self.context.root_path / "modules" / "consensus"
        if consensus_path.exists():
            for algo in self.consensus_modules:
                if algo == "none":
                    algo_path = self.context.root_path / "modules" / "type" / "none"
                elif "dag" in algo:
                    algo_path = consensus_path / algo.replace("-", "_")
                else:
                    algo_path = consensus_path / algo.replace("-", "_")

                if algo_path.exists():
                    files = list(algo_path.glob("*.c"))
                    headers = list(algo_path.glob("*.h"))
                    consensus_info[algo] = {
                        "files": len(files),
                        "headers": len(headers),
                        "path": str(algo_path),
                        "status": "implemented"
                    }
                else:
                    consensus_info[algo] = {
                        "status": "not_found",
                        "path": str(algo_path)
                    }

        return consensus_info

    async def analyze_build_configuration(self) -> Dict[str, Any]:
        """Анализ конфигурации сборки CellFrame SDK"""
        build_info = {}

        cmake_path = self.context.root_path / "CMakeLists.txt"
        if cmake_path.exists():
            with open(cmake_path, 'r', encoding='utf-8') as f:
                cmake_content = f.read()

            # Анализ CELLFRAME_MODULES
            modules_match = None
            for line in cmake_content.split('\n'):
                if "CELLFRAME_MODULES" in line and "set(" in line:
                    modules_match = line
                    break

            if modules_match:
                # Извлечение списка модулей
                modules_start = modules_match.find('"') + 1
                modules_end = modules_match.rfind('"')
                if modules_start > 0 and modules_end > modules_start:
                    modules_str = modules_match[modules_start:modules_end]
                    modules = [m.strip() for m in modules_str.split() if m.strip()]
                    build_info["default_modules"] = modules

            # Анализ опций сборки
            options = []
            if "CELLFRAME_MODULES" in cmake_content:
                options.append("CELLFRAME_MODULES")
            if "BUILD_CELLFRAME_SDK_TESTS" in cmake_content:
                options.append("BUILD_CELLFRAME_SDK_TESTS")
            if "DAP_INT128_SUPPORT" in cmake_content:
                options.append("DAP_INT128_SUPPORT")

            build_info["cmake"] = {
                "path": str(cmake_path),
                "build_options": options
            }

        return build_info

    async def analyze_blockchain_operations(self) -> Dict[str, Any]:
        """Анализ блокчейн операций CellFrame SDK"""
        blockchain_info = {}

        # Анализ основных структур данных
        chain_header = self.context.root_path / "modules" / "chain" / "include" / "dap_chain.h"
        if chain_header.exists():
            with open(chain_header, 'r', encoding='utf-8') as f:
                content = f.read()

            # Поиск основных структур
            structures = []
            lines = content.split('\n')
            current_struct = None
            brace_count = 0

            for line in lines:
                if line.strip().startswith('typedef struct'):
                    current_struct = line.split()[2] if len(line.split()) > 2 else None
                    brace_count = 0
                elif current_struct and '{' in line:
                    brace_count += 1
                elif current_struct and '}' in line:
                    brace_count -= 1
                    if brace_count <= 0:
                        structures.append(current_struct)
                        current_struct = None

            blockchain_info["data_structures"] = structures

            # Анализ констант
            constants = []
            for line in lines:
                if line.strip().startswith('#define') and ('DAP_CHAIN' in line or 'ATOM' in line):
                    const_name = line.split()[1] if len(line.split()) > 1 else ""
                    if const_name:
                        constants.append(const_name)

            blockchain_info["constants"] = constants

        return blockchain_info

    async def find_transaction_examples(self) -> List[Dict[str, Any]]:
        """Поиск примеров транзакций в CellFrame SDK"""
        examples = []

        # Поиск в модулях compose и chain
        search_paths = [
            self.context.root_path / "modules" / "compose",
            self.context.root_path / "modules" / "chain"
        ]

        for search_path in search_paths:
            if search_path.exists():
                for c_file in search_path.glob("*.c"):
                    with open(c_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Поиск функций связанных с транзакциями
                    if 'transaction' in content.lower() or 'tx_' in content.lower():
                        examples.append({
                            "file": str(c_file),
                            "module": search_path.name,
                            "has_transactions": True,
                            "functions": self._extract_functions(content)
                        })

        return examples

    def _extract_functions(self, content: str) -> List[str]:
        """Извлечение имен функций из кода"""
        functions = []
        lines = content.split('\n')

        for line in lines:
            line = line.strip()
            if line and not line.startswith('//') and not line.startswith('/*'):
                # Поиск сигнатур функций
                if ('(' in line and ')' in line and
                    ('int ' in line or 'void ' in line or 'bool ' in line or 'char ' in line or
                     'dap_' in line or 'cellframe_' in line)):
                    # Упрощенная проверка - берем первое слово после типа возврата
                    parts = line.split()
                    if len(parts) >= 2:
                        func_name = parts[1].split('(')[0] if '(' in parts[1] else parts[1]
                        if func_name and not func_name.startswith('*'):
                            functions.append(func_name)

        return functions[:10]  # Ограничиваем до 10 функций

    async def analyze_networking_features(self) -> Dict[str, Any]:
        """Анализ сетевых функций CellFrame SDK"""
        network_info = {}

        net_path = self.context.root_path / "modules" / "net"
        if net_path.exists():
            # Анализ основных компонентов
            components = {}
            for item in net_path.iterdir():
                if item.is_dir():
                    files = list(item.glob("*.c"))
                    headers = list(item.glob("*.h"))
                    components[item.name] = {
                        "files": len(files),
                        "headers": len(headers),
                        "path": str(item)
                    }

            network_info["components"] = components

            # Анализ сетевых протоколов
            protocols = []
            for c_file in net_path.glob("**/*.c"):
                with open(c_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Поиск упоминаний протоколов
                if 'tcp' in content.lower():
                    protocols.append('TCP')
                if 'udp' in content.lower():
                    protocols.append('UDP')
                if 'http' in content.lower():
                    protocols.append('HTTP')
                if 'websocket' in content.lower():
                    protocols.append('WebSocket')

            network_info["protocols"] = list(set(protocols))

        return network_info

class CellFrameMCPServer:
    """MCP сервер для CellFrame SDK"""

    def __init__(self):
        self.context = CellFrameSDKContext("/home/naeper/work/cellframe-node/cellframe-sdk")
        self.tools = CellFrameMCPTools(self.context)
        self.server = Server("cellframe-sdk-mcp-server")

    async def handle_list_tools(self) -> List[Tool]:
        """Список доступных инструментов"""
        return [
            Tool(
                name="analyze_chain_modules",
                description="Анализ модулей блокчейн цепочки CellFrame SDK (chain, wallet, mempool)",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="analyze_service_modules",
                description="Анализ сервисных модулей CellFrame SDK (VPN, staking, exchange)",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="analyze_consensus_algorithms",
                description="Анализ алгоритмов консенсуса CellFrame SDK (PoA, PoW, DAG)",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="analyze_build_configuration",
                description="Анализ конфигурации сборки CellFrame SDK",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="analyze_blockchain_operations",
                description="Анализ блокчейн операций и структур данных",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="find_transaction_examples",
                description="Поиск примеров работы с транзакциями",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="analyze_networking_features",
                description="Анализ сетевых функций и протоколов",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="get_project_overview",
                description="Получение общего обзора проекта CellFrame SDK",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            )
        ]

    async def handle_call_tool(self, name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        """Обработка вызова инструмента"""
        try:
            if name == "analyze_chain_modules":
                result = await self.tools.analyze_chain_modules()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "analyze_service_modules":
                result = await self.tools.analyze_service_modules()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "analyze_consensus_algorithms":
                result = await self.tools.analyze_consensus_algorithms()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "analyze_build_configuration":
                result = await self.tools.analyze_build_configuration()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "analyze_blockchain_operations":
                result = await self.tools.analyze_blockchain_operations()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "find_transaction_examples":
                result = await self.tools.find_transaction_examples()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "analyze_networking_features":
                result = await self.tools.analyze_networking_features()
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )]

            elif name == "get_project_overview":
                overview = {
                    "name": "CellFrame SDK",
                    "description": "Blockchain platform SDK with quantum-resistant features",
                    "focus": "Decentralized applications and blockchain infrastructure",
                    "language": "C",
                    "key_features": [
                        "Multiple consensus algorithms (PoA, PoW, DAG)",
                        "Modular service architecture",
                        "Cross-platform support",
                        "High-performance blockchain operations",
                        "Cryptographic security features"
                    ],
                    "main_modules": [
                        "chain - Core blockchain functionality",
                        "wallet - Wallet management",
                        "net - Network communication",
                        "consensus - Consensus algorithms",
                        "service - Additional services (VPN, staking, etc.)"
                    ],
                    "supported_consensus": [
                        "DAG PoA (Proof of Authority)",
                        "DAG PoS (Proof of Stake)",
                        "Block PoW (Proof of Work)",
                        "ESBOCS (Enhanced Scalable Blockchain Consensus)",
                        "No consensus (for testing)"
                    ]
                }
                return [TextContent(
                    type="text",
                    text=json.dumps(overview, indent=2, ensure_ascii=False)
                )]

            else:
                raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            logger.error(f"Error calling tool {name}: {e}")
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

async def main():
    """Главная функция MCP сервера"""
    server = CellFrameMCPServer()

    # Регистрация обработчиков
    @server.server.list_tools()
    async def handle_list_tools():
        return await server.handle_list_tools()

    @server.server.call_tool()
    async def handle_call_tool(name: str, arguments: Dict[str, Any]):
        return await server.handle_call_tool(name, arguments)

    # Запуск сервера
    logger.info("Starting CellFrame SDK MCP Server...")
    logger.info("Available tools:")
    tools = await server.handle_list_tools()
    for tool in tools:
        logger.info(f"  - {tool.name}: {tool.description}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            server.server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
