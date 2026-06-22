import json

import httpx

from app.main import GenerateInput
from app.services import generation_provider as gp


def _sample_input() -> GenerateInput:
    return GenerateInput(
        industry="restaurant",
        business_name="A店",
        main_offer="双人餐",
        avg_ticket="88",
        audience="白领",
        goal="引流",
    )


def test_provider_success_normalized(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_API_KEY", "k")

    class DummyResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "title": "T",
                                    "hook_3s": "H",
                                    "voiceover": "V",
                                    "shots": ["s1", "s2"],
                                    "cta": "C",
                                    "duration_sec": 28,
                                },
                                ensure_ascii=False,
                            )
                        }
                    }
                ]
            }

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            return DummyResp()

    monkeypatch.setattr(httpx, "Client", DummyClient)
    result = gp.generate_script(_sample_input(), 0)
    assert set(result.keys()) == {"title", "hook_3s", "voiceover", "shots", "duration_sec", "cta"}
    assert result["title"] == "T"


def test_provider_failure_fallback(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.setenv("LLM_RETRIES", "1")

    class BoomClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            raise RuntimeError("network down")

    monkeypatch.setattr(httpx, "Client", BoomClient)
    result = gp.generate_script(_sample_input(), 1)
    assert "A店选题2" in result["title"]
    assert result["cta"] == "评论区回复关键词，领取到店福利"


def test_local_provider_by_default(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    result = gp.generate_script(_sample_input(), 2)
    assert result["title"].startswith("A店选题3")
    assert isinstance(result["shots"], list)
