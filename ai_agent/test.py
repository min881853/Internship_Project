from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import joblib
import numpy as np
from ollama import chat, Client
from dotenv import load_dotenv

load_dotenv()

# ----------------------------
# Ollama Config
# ----------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "https://sisterless-suk-uncirculative.ngrok-free.dev")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

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
    if not MODELS_LOADED: raise ToolError("ICMP model not loaded")
    features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
    pred = rf_model_icmp.predict(features)[0]
    probs = rf_model_icmp.predict_proba(features)[0]
    prob_dict = dict(zip(rf_model_icmp.classes_, probs))
    result = {
        "protocol": "ICMP",
        "prediction": str(pred),
        "probability_scores": {str(k): float(v) for k, v in prob_dict.items()},
        "confidence": float(max(probs))
    }
    return json.dumps(result)

def classify_tcp(packet_count: float, byte_count: float, packet_rate: float, byte_rate: float, cpu_utilization: float) -> str:
    if not MODELS_LOADED: raise ToolError("TCP model not loaded")
    features = np.array([[packet_count, byte_count, packet_rate, byte_rate, cpu_utilization]])
    pred = rf_model_tcp.predict(features)[0]
    probs = rf_model_tcp.predict_proba(features)[0]
    prob_dict = dict(zip(rf_model_tcp.classes_, probs))
    result = {
        "protocol": "TCP",
        "prediction": str(pred),
        "probability_scores": {str(k): float(v) for k, v in prob_dict.items()},
        "confidence": float(max(probs))
    }
    return json.dumps(result)

TOOL_FUNCS: Dict[str, Callable[..., str]] = {
    "classify_icmp": classify_icmp,
    "classify_tcp": classify_tcp,
}

# ----------------------------
# ReAct Prompting
# ----------------------------
SYSTEM_PROMPT = """You are a network security AI assistant specialized in DDoS detection.
When asked to classify network traffic, you MUST use the appropriate classification tool.

Available Tools:
- classify_icmp(packet_count, byte_count, packet_rate, byte_rate, cpu_utilization) - Classifies ICMP traffic
- classify_tcp(packet_count, byte_count, packet_rate, byte_rate, cpu_utilization) - Classifies TCP traffic

To call a tool, respond ONLY with this JSON format:
{"tool": "function_name", "args": {"arg_name": value}}

After receiving a 'Tool Result', provide a detailed analysis including:
1. The predicted classification (Normal or DDoS)
2. Probability scores for each class
3. Confidence level (highest probability)
4. Risk assessment based on the classification result

Format your response clearly with:
- PREDICTION: [Normal/DDoS]
- CONFIDENCE: [percentage]%
- PROBABILITIES: [class: percentage for each class]
- ASSESSMENT: [Brief risk analysis]
"""

# ----------------------------
# Ollama client
# ----------------------------
class OllamaClient:
    def __init__(self):
        self.base_url = OLLAMA_BASE_URL
        self.model = OLLAMA_MODEL
        self.client = Client(host=self.base_url)

    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Callable]] = None) -> Any:
        return self.client.chat(model=self.model, messages=messages, tools=tools or [])

# ----------------------------
# Agent Logic
# ----------------------------
class OllamaAgent:
    def __init__(self):
        self.client = OllamaClient()
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def run_turn(self, user_text: str):
        self.messages.append({"role": "user", "content": user_text})
        
        response = self.client.chat(self.messages, tools=[classify_icmp, classify_tcp])
        
        self.messages.append(response.message)
        if response.message.tool_calls:
            for call in response.message.tool_calls:
                # Convert args to float
                try:
                    args = {k: float(v) for k, v in call.function.arguments.items()}
                except ValueError as e:
                    return f"Error converting args to float: {e}"
                
                print(f"[*] Executing Tool: {call.function.name}({args})")
                result = TOOL_FUNCS[call.function.name](**args)
                
                self.messages.append({"role": "tool", "tool_name": call.function.name, "content": str(result)})
            
            final_response = self.client.chat(self.messages, tools=[classify_icmp, classify_tcp])
            return final_response.message.content
        
        return response.message.content

def main():
    agent = OllamaAgent()
    print(f"Security Agent ready. (Type 'exit' to quit)")
    print(f"Connected to: {OLLAMA_BASE_URL}")
    print(f"Model: {OLLAMA_MODEL}")
    while True:
        user = input("\nUser: ")
        if user.lower() in ["exit", "quit"]: break
        ans = agent.run_turn(user)
        print(f"\nAI: {ans}")

if __name__ == "__main__":
    main()
