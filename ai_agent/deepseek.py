"""
AI Agent using Ollama (OpenAI-compatible) + Local ML tools (RF classifiers)

Requirements:
  pip install requests joblib numpy python-dotenv

Setup Ollama:
  Install Ollama from https://ollama.ai/
  Run: ollama serve
  Pull a model: ollama pull llama3.2
  Optional: Set $env:OLLAMA_MODEL="your_model"

Run:
  python deepseek.py
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import joblib
import numpy as np
import requests
from dotenv import load_dotenv
load_dotenv()

# ----------------------------
# Ollama Config
# ----------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")  # default model, adjust as needed


# ----------------------------
# Load pre-trained Random Forest models
# ----------------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

try:
    rf_model_icmp = joblib.load(os.path.join(MODEL_DIR, "rf_model_1.joblib"))
    rf_model_tcp = joblib.load(os.path.join(MODEL_DIR, "rf_model_6.joblib"))
    MODELS_LOADED = True
except Exception as e:
    print(f"Warning: Could not load RF models: {e}")
    MODELS_LOADED = False


# ----------------------------
# Tools
# ----------------------------
class ToolError(Exception):
    pass


def classify_icmp(packet_count: float, byte_count: float, packet_rate: float, byte_rate: float, cpu_utilization: float) -> str:
    if not MODELS_LOADED:
        raise ToolError("ICMP model not loaded")

    features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
    pred = rf_model_icmp.predict(features)[0]
    return f"ICMP Classification: {pred}"


def classify_tcp(packet_count: float, byte_count: float, packet_rate: float, byte_rate: float, cpu_utilization: float) -> str:
    if not MODELS_LOADED:
        raise ToolError("TCP model not loaded")

    features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
    pred = rf_model_tcp.predict(features)[0]
    return f"TCP Classification: {pred}"


TOOL_FUNCS: Dict[str, Callable[..., str]] = {
    "classify_icmp": classify_icmp,
    "classify_tcp": classify_tcp,
}

# DeepSeek (OpenAI-compatible) tool schema
TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "classify_icmp",
            "description": "Classify ICMP network traffic as Normal or DDoS using ML model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_count": {"type": "number"},
                    "byte_count": {"type": "number"},
                    "packet_rate": {"type": "number"},
                    "byte_rate": {"type": "number"},
                    "cpu_utilization": {"type": "number"},
                },
                "required": ["packet_count", "byte_count", "packet_rate", "byte_rate", "cpu_utilization"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify_tcp",
            "description": "Classify TCP network traffic as Normal or DDoS using ML model.",
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_count": {"type": "number"},
                    "byte_count": {"type": "number"},
                    "packet_rate": {"type": "number"},
                    "byte_rate": {"type": "number"},
                    "cpu_utilization": {"type": "number"},
                },
                "required": ["packet_count", "byte_count", "packet_rate", "byte_rate", "cpu_utilization"],
                "additionalProperties": False,
            },
        },
    },
]


# ----------------------------
# Ollama client (requests)
# ----------------------------
class OllamaClient:
    def __init__(self, timeout: int = 120):
        self.base_url = OLLAMA_BASE_URL
        self.model = OLLAMA_MODEL
        self.timeout = timeout

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/chat/completions"
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Content-Type": "application/json",
        }

        r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        if not r.ok:
            raise RuntimeError(f"Ollama error {r.status_code}: {r.text}")

        return r.json()


# ----------------------------
# Agent
# ----------------------------
SYSTEM_PROMPT = (
    "You are a network security AI assistant.\n"
    "When the user asks to classify traffic and provides these fields:\n"
    "packet_count, byte_count, packet_rate, byte_rate, cpu_utilization\n"
    "you MUST call the correct tool:\n"
    "- classify_icmp for ICMP traffic\n"
    "- classify_tcp for TCP traffic\n"
    "Return the tool result clearly.\n"
)

@dataclass
class AgentState:
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, role: str, content: str, **extra: Any) -> None:
        msg = {"role": role, "content": content}
        msg.update(extra)
        self.messages.append(msg)


class OllamaAgent:
    def __init__(self):
        self.client = OllamaClient()
        self.state = AgentState()
        self.state.add("system", SYSTEM_PROMPT)

    def _run_tool(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        OpenAI-style tool_call:
          {
            "id": "...",
            "type": "function",
            "function": {"name": "...", "arguments": "{\"a\":1}"}
          }

        Tool result message must include tool_call_id:
          {"role":"tool","tool_call_id":"...","content":"..."}
        """
        call_id = tool_call.get("id", "toolcall")
        fn = tool_call.get("function", {})
        name = fn.get("name")
        arg_str = fn.get("arguments", "{}")

        if name not in TOOL_FUNCS:
            return {"role": "tool", "tool_call_id": call_id, "content": f"Tool '{name}' not found."}

        try:
            args = json.loads(arg_str) if isinstance(arg_str, str) else (arg_str or {})
        except json.JSONDecodeError:
            return {"role": "tool", "tool_call_id": call_id, "content": f"Bad JSON arguments: {arg_str}"}

        try:
            result = TOOL_FUNCS[name](**args)
        except ToolError as e:
            result = f"Tool error: {e}"
        except TypeError as e:
            result = f"Arguments mismatch: {e}"
        except Exception as e:
            result = f"Unexpected tool error: {e}"

        return {"role": "tool", "tool_call_id": call_id, "content": str(result)}

    def run_turn(self, user_text: str, max_tool_rounds: int = 5) -> str:
        self.state.add("user", user_text)

        resp = self.client.chat(self.state.messages, tools=TOOLS_SCHEMA, temperature=0.2)
        msg = resp["choices"][0]["message"]
        self.state.messages.append(msg)

        rounds = 0
        while rounds < max_tool_rounds and msg.get("tool_calls"):
            rounds += 1

            for tc in msg["tool_calls"]:
                tool_msg = self._run_tool(tc)
                self.state.messages.append(tool_msg)

            resp = self.client.chat(self.state.messages, tools=TOOLS_SCHEMA, temperature=0.2)
            msg = resp["choices"][0]["message"]
            self.state.messages.append(msg)

        return (msg.get("content") or "").strip()


def main():
    agent = OllamaAgent()
    client = OllamaClient()  # to get config for print
    print(f"✅ Ollama Agent ready | base_url={client.base_url} | model={client.model}")
    print("Type 'exit' to quit.\n")

    while True:
        user = input("You: ").strip()
        if user.lower() in {"exit", "quit"}:
            break
        ans = agent.run_turn(user)
        print(f"\nAgent: {ans}\n")


if __name__ == "__main__":
    main()
