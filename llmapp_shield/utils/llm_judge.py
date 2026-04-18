# llmapp_shield/utils/llm_judge.py
"""
LLM-as-Judge — Optional semantic validation of findings.

Uses a local LLM (Ollama) or cloud LLM (Groq) to validate whether
static analysis findings are likely true positives or false positives.

This is intentionally optional and lightweight — the core scanner
does not require any LLM API to function.
"""

from __future__ import annotations

import json
from typing import Optional

import httpx

from llmapp_shield.models import Finding


_JUDGE_PROMPT = """You are a security expert reviewing potential LLM application vulnerabilities.

For each finding below, analyze the code snippet and determine if it's a TRUE POSITIVE
(genuine security vulnerability) or FALSE POSITIVE (not actually vulnerable).

Be conservative: when uncertain, mark as true positive.

Finding:
- Rule: {rule_id}
- Title: {title}
- Severity: {severity}
- Code:
{code_snippet}

Description: {description}

Respond with ONLY valid JSON in this exact format:
{{"verdict": "true_positive" | "false_positive", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}"""


class LLMJudge:
    """
    Validates findings using a local or cloud LLM.

    Providers:
    - ollama: Local Ollama instance (privacy-preserving)
    - groq: Groq cloud API (fast, requires GROQ_API_KEY env var)
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "llama3.2",
        endpoint: str = "http://localhost:11434",
        timeout: float = 30.0,
    ) -> None:
        self.provider = provider
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def validate(self, findings: list[Finding]) -> list[Finding]:
        """
        Validate findings, filtering out likely false positives.

        Returns filtered list with updated confidence scores.
        """
        validated: list[Finding] = []

        for finding in findings:
            # Only judge medium+ severity (skip low to save API calls)
            if finding.severity.order < 2:
                validated.append(finding)
                continue

            verdict = self._judge_finding(finding)
            if verdict is None:
                # Judge failed — keep finding as-is
                validated.append(finding)
                continue

            if verdict["verdict"] == "false_positive" and verdict["confidence"] >= 0.8:
                # High confidence false positive — skip
                finding_copy = finding.model_copy(update={
                    "false_positive_likelihood": verdict["confidence"],
                    "detected_by": f"{finding.detected_by}+llm_judge_fp",
                })
                # Still include but mark as likely FP
                finding_copy = finding.model_copy(update={"confidence": 1.0 - verdict["confidence"]})
                if finding_copy.confidence > 0.3:
                    validated.append(finding_copy)
            else:
                # True positive — update confidence
                new_confidence = min(0.99, finding.confidence * (0.5 + verdict["confidence"] * 0.5))
                validated.append(finding.model_copy(update={
                    "confidence": new_confidence,
                    "detected_by": f"{finding.detected_by}+llm_judge",
                }))

        return validated

    def _judge_finding(self, finding: Finding) -> Optional[dict]:
        """Call the LLM to judge a single finding."""
        prompt = _JUDGE_PROMPT.format(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity.value,
            code_snippet=finding.code_snippet or "(no code snippet available)",
            description=finding.description,
        )

        try:
            if self.provider == "ollama":
                return self._call_ollama(prompt)
            elif self.provider == "groq":
                return self._call_groq(prompt)
            else:
                return None
        except Exception:
            return None

    def _call_ollama(self, prompt: str) -> Optional[dict]:
        """Call local Ollama API."""
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "")
            return _parse_judge_response(text)

    def _call_groq(self, prompt: str) -> Optional[dict]:
        """Call Groq cloud API."""
        import os
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY environment variable not set")

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model or "llama3-8b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            return _parse_judge_response(text)


def _parse_judge_response(text: str) -> Optional[dict]:
    """Parse the JSON response from the LLM judge."""
    try:
        data = json.loads(text.strip())
        if "verdict" in data and "confidence" in data:
            return data
    except (json.JSONDecodeError, KeyError):
        pass
    return None
