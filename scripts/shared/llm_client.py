#!/usr/bin/env python3
"""
shared/llm_client.py

Centralized LLM interaction wrapper with configurable model fallback chain.
Replaces duplicated litellm patterns across ai_briefing.py, ai_classify_web.py, and ai_typosquat.py.

Usage:
    from shared.llm_client import LLMClient
    
    client = LLMClient()
    
    # Text completion
    response = client.complete("Analyze this data...", system="You are an analyst.")
    
    # JSON completion with automatic parsing
    data = client.complete_json("Classify these domains...", system="Return JSON only.")
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from litellm import completion

load_dotenv()
logger = logging.getLogger(__name__)

# Central model configuration — single source of truth
# Updated 2026-02-21 per Anthropic API deprecation
DEFAULT_MODEL_CHAIN = [
    "anthropic/claude-sonnet-4-5-20250929",  # Primary (pinned snapshot)
    "gemini/gemini-3-pro-preview",           # Secondary
    "gpt-4o",                                # Tertiary
    "gemini/gemini-flash-latest",            # Emergency fallback
]


class LLMClient:
    """
    Wrapper around litellm with configurable model fallback chain and JSON output support.
    
    Features:
    - Automatic fallback through model chain on failure
    - JSON mode with code fence stripping
    - Structured logging of model attempts
    - API key passthrough for services that need explicit keys
    """
    
    def __init__(self, models: Optional[List[str]] = None):
        """
        Args:
            models: Ordered list of model identifiers for litellm.
                    Falls through the list on failure. Defaults to DEFAULT_MODEL_CHAIN.
        """
        self.models = models or DEFAULT_MODEL_CHAIN
    
    def _get_api_key(self, model: str) -> Optional[str]:
        """Returns the appropriate API key for models that need explicit passthrough."""
        if "anthropic" in model:
            return os.getenv("ANTHROPIC_API_KEY")
        return None
    
    def complete(
        self,
        prompt: str,
        system: str = "",
        json_mode: bool = False,
        temperature: float = 0.3
    ) -> Optional[str]:
        """
        Send a completion request, trying each model in the chain until one succeeds.
        
        Args:
            prompt: User message content.
            system: System message content.
            json_mode: If True, requests JSON response format.
            temperature: Sampling temperature.
        
        Returns:
            The response content string, or None if all models fail.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        kwargs: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        
        last_error = None
        model_used = None
        
        for model in self.models:
            try:
                logger.info(f"Attempting completion with {model}...")
                
                api_key = self._get_api_key(model)
                if api_key:
                    kwargs["api_key"] = api_key
                elif "api_key" in kwargs:
                    del kwargs["api_key"]
                
                response = completion(model=model, **kwargs)
                content = response.choices[0].message.content
                model_used = getattr(response, 'model', model)
                
                logger.info(f"Success with {model_used}")
                return content
                
            except Exception as e:
                last_error = e
                logger.warning(f"{model} failed: {e}")
                continue
        
        logger.error(f"All {len(self.models)} models failed. Last error: {last_error}")
        return None
    
    def complete_json(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3
    ) -> Optional[Dict]:
        """
        Send a completion request and parse the response as JSON.
        
        Handles common LLM output quirks:
        - Code fences (```json ... ```)
        - Leading/trailing whitespace
        - Markdown formatting artifacts
        
        Args:
            prompt: User message content.
            system: System message content.
            temperature: Sampling temperature.
        
        Returns:
            Parsed JSON as a dict, or None if all models fail or JSON is invalid.
        """
        content = self.complete(prompt, system=system, json_mode=True, temperature=temperature)
        
        if content is None:
            return None
        
        return self._parse_json_response(content)
    
    @staticmethod
    def _parse_json_response(content: str) -> Optional[Dict]:
        """
        Extracts and parses JSON from LLM response text.
        Handles code fences and other formatting artifacts.
        """
        # Strip code fences
        cleaned = content.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1]
            if "```" in cleaned:
                cleaned = cleaned.split("```", 1)[0]
        elif "```" in cleaned:
            # Generic code fence
            parts = cleaned.split("```")
            if len(parts) >= 3:
                cleaned = parts[1]
            else:
                cleaned = cleaned.replace("```", "")
        
        try:
            return json.loads(cleaned.strip())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from LLM response: {e}")
            logger.debug(f"Raw content: {content[:500]}")
            return None
