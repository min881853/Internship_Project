"""
Local AI Agent for Ollama (correct tool-calling format)

Requirements:
  pip install requests

Run:
  ollama serve
  set OLLAMA_MODEL=llama3.1   (Windows PowerShell: $env:OLLAMA_MODEL="llama3.1")
  python ollama_agent.py
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import joblib
import numpy as np
import requests

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:0.8b")

# Load pre-trained Random Forest models for network traffic classification
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'model')
try:
    rf_model_icmp = joblib.load(os.path.join(MODEL_DIR, 'rf_model_1.joblib'))
    rf_model_tcp = joblib.load(os.path.join(MODEL_DIR, 'rf_model_6.joblib'))
    MODELS_LOADED = True
except Exception as e:
    print(f"Warning: Could not load RF models: {e}")
    MODELS_LOADED = False

# ----------------------------
# Tools
# ----------------------------
class ToolError(Exception):
    pass


def calculator(expression: str) -> str:
    if not re.fullmatch(r"[0-9\.\+\-\*\/\%\(\)\s]+", expression):
        raise ToolError("Unsafe expression. Allowed: digits + . + - * / % ( ) and spaces.")
    try:
        result = eval(expression, {"__builtins__": {}}, {})
    except Exception as e:
        raise ToolError(f"Calculator error: {e}") from e
    return str(result)


def shell(command: str) -> str:
    # Strongly restrict allowed commands for safety
    allow = {"ls", "pwd", "whoami", "date"}
    parts = shlex.split(command)
    if not parts:
        raise ToolError("Empty command.")
    if parts[0] not in allow:
        raise ToolError(f"Command '{parts[0]}' not allowed. Allowed: {sorted(allow)}")
    try:
        out = subprocess.check_output(parts, stderr=subprocess.STDOUT, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        raise ToolError(f"Shell error: {e.output}") from e


def classify_icmp(packet_count: float, byte_count: float, packet_rate: float, byte_rate: float, cpu_utilization: float) -> str:
    """
    Classify ICMP traffic as Normal or DDoS using a Random Forest model.
    
    Args:
        packet_count: Number of packets
        byte_count: Total bytes
        packet_rate: Packets per second
        byte_rate: Bytes per second
        cpu_utilization: CPU utilization percentage
    
    Returns:
        Classification result (Normal_ICMP or DDoS_ICMP)
    """
    if not MODELS_LOADED:
        raise ToolError("ICMP model not loaded")
    
    try:
        features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
        prediction = rf_model_icmp.predict(features)[0]
        return f"ICMP Classification: {prediction}"
    except Exception as e:
        raise ToolError(f"ICMP classification error: {e}") from e


def classify_tcp(packet_count: float, byte_count: float, packet_rate: float, byte_rate: float, cpu_utilization: float) -> str:
    """
    Classify TCP traffic as Normal or DDoS using a Random Forest model.
    
    Args:
        packet_count: Number of packets
        byte_count: Total bytes
        packet_rate: Packets per second
        byte_rate: Bytes per second
        cpu_utilization: CPU utilization percentage
    
    Returns:
        Classification result (Normal_TCP or DDoS_TCP)
    """
    if not MODELS_LOADED:
        raise ToolError("TCP model not loaded")
    
    try:
        features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
        prediction = rf_model_tcp.predict(features)[0]
        return f"TCP Classification: {prediction}"
    except Exception as e:
        raise ToolError(f"TCP classification error: {e}") from e


TOOL_FUNCS: Dict[str, Callable[..., str]] = {
    # "calculator": calculator,
    # "shell": shell,
    "classify_icmp": classify_icmp,
    "classify_tcp": classify_tcp,
}

# Ollama tool schema (supported by /api/chat)
TOOLS_SCHEMA: List[Dict[str, Any]] = [
    # {
    #     "type": "function",
    #     "function": {
    #         "name": "calculator",
    #         "description": "Evaluate a math expression. Example: '((2+3)*4)/5'",
    #         "parameters": {
    #             "type": "object",
    #             "properties": {
    #                 "expression": {"type": "string", "description": "Math expression to evaluate"},
    #             },
    #             "required": ["expression"],
    #         },
    #     },
    # },
    # {
    #     "type": "function",
    #     "function": {
    #         "name": "shell",
    #         "description": "Run a safe shell command from an allowlist (ls, pwd, whoami, date).",
    #         "parameters": {
    #             "type": "object",
    #             "properties": {
    #                 "command": {"type": "string", "description": "Shell command to run"},
    #             },
    #             "required": ["command"],
    #         },
    #     },
    # },
    {
        "type": "function",
        "function": {
            "name": "classify_icmp",
            "description": "Classify ICMP network traffic as Normal or DDoS using machine learning model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_count": {"type": "number", "description": "Number of packets"},
                    "byte_count": {"type": "number", "description": "Total bytes transmitted"},
                    "packet_rate": {"type": "number", "description": "Packets per second"},
                    "byte_rate": {"type": "number", "description": "Bytes per second"},
                    "cpu_utilization": {"type": "number", "description": "CPU utilization percentage (0-100)"},
                },
                "required": ["packet_count", "byte_count", "packet_rate", "byte_rate", "cpu_utilization"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify_tcp",
            "description": "Classify TCP network traffic as Normal or DDoS using machine learning model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_count": {"type": "number", "description": "Number of packets"},
                    "byte_count": {"type": "number", "description": "Total bytes transmitted"},
                    "packet_rate": {"type": "number", "description": "Packets per second"},
                    "byte_rate": {"type": "number", "description": "Bytes per second"},
                    "cpu_utilization": {"type": "number", "description": "CPU utilization percentage (0-100)"},
                },
                "required": ["packet_count", "byte_count", "packet_rate", "byte_rate", "cpu_utilization"],
            },
        },
    },
]


# ----------------------------
# Ollama client
# ----------------------------
class OllamaClient:
    def __init__(self, host: str = OLLAMA_HOST, model: str = MODEL, timeout: int = 120):
        self.host = host
        self.model = model
        self.timeout = timeout

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        stream: bool = False,
        temperature: float = 0.2,
    ) -> Dict[str, Any]:
        url = f"{self.host}/api/chat"
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = tools

        r = requests.post(url, json=payload, timeout=self.timeout)
        print(f"DEBUG: Ollama response status={r.status_code} content={r.text[:200]}...")
        # Helpful debug if 400 happens again
        if not r.ok:
            raise RuntimeError(f"Ollama error {r.status_code}: {r.text}")

        return r.json()


# ----------------------------
# Agent
# ----------------------------
SYSTEM_PROMPT = (
    "You are a helpful local AI agent running via Ollama with capabilities for network traffic analysis.\n"
    "You can use the following tools:\n"
    "- classify_icmp: To classify ICMP network traffic as Normal or DDoS\n"
    "- classify_tcp: To classify TCP network traffic as Normal or DDoS\n"
    "Use tools when needed to provide accurate analysis and classifications.\n"
    "When users ask about network traffic, offer to classify it using the appropriate tool.\n"
)

@dataclass
class AgentState:
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, role: str, content: str, **extra: Any) -> None:
        msg = {"role": role, "content": content}
        msg.update(extra)
        self.messages.append(msg)


class OllamaAgent:
    def __init__(self, model: str = MODEL, host: str = OLLAMA_HOST):
        self.client = OllamaClient(host=host, model=model)
        self.state = AgentState()
        self.state.add("system", SYSTEM_PROMPT)

    def _run_tool(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ollama tool_call format (from docs):
          {
            "type": "function",
            "function": {
              "index": 0,
              "name": "tool_name",
              "arguments": { ... }   # dict, NOT JSON string
            }
          }
        Tool result message must include tool_name:
          {"role":"tool","tool_name":"tool_name","content":"result"}
        """
        fn = tool_call.get("function", {})
        name = fn.get("name")
        args = fn.get("arguments") or {}

        if name not in TOOL_FUNCS:
            return {"role": "tool", "tool_name": str(name), "content": f"Tool '{name}' not found."}

        try:
            result = TOOL_FUNCS[name](**args)
        except ToolError as e:
            result = f"Tool error: {e}"
        except TypeError as e:
            result = f"Arguments mismatch: {e}"
        except Exception as e:
            result = f"Unexpected tool error: {e}"

        return {"role": "tool", "tool_name": name, "content": str(result)}

    def run_turn(self, user_text: str, max_tool_rounds: int = 5) -> str:
        self.state.add("user", user_text)

        resp = self.client.chat(self.state.messages, tools=TOOLS_SCHEMA, stream=False)
        assistant_msg = resp.get("message", {})
        self.state.messages.append(assistant_msg)

        rounds = 0
        while rounds < max_tool_rounds and assistant_msg.get("tool_calls"):
            rounds += 1

            # execute all tool calls
            for tc in assistant_msg["tool_calls"]:
                tool_msg = self._run_tool(tc)
                self.state.messages.append(tool_msg)

            # ask model again with tool results included
            resp = self.client.chat(self.state.messages, tools=TOOLS_SCHEMA, stream=False)
            assistant_msg = resp.get("message", {})
            self.state.messages.append(assistant_msg)

        return (assistant_msg.get("content") or "").strip()


def main():
    agent = OllamaAgent(model=MODEL, host=OLLAMA_HOST)
    print(f"✅ Ollama Agent ready | host={OLLAMA_HOST} | model={MODEL}")
    print("Type 'exit' to quit.\n")

    while True:
        user = input("You: ").strip()
        if user.lower() in {"exit", "quit"}:
            break
        ans = agent.run_turn(user)
        print(f"\nAgent: {ans}\n")


if __name__ == "__main__":
    main()