# Prewise Qwen 3.5 four-adapter runtime

The runtime serves one pinned `Qwen/Qwen3.5-9B` base model and four LoRA
specialists through one OpenAI-compatible vLLM process:

- `prewise-message-context`
- `prewise-web-context`
- `prewise-explanation`
- `prewise-legal-rag`

Install the already-downloaded, pinned bundle without exposing any token:

```bash
python scripts/install_qwen35_adapters.py \
  --zip /workspace/prewise-qwen35-9b-four-adapters/prewise-qwen35-9b-four-adapters-A40.zip \
  --checksum /workspace/prewise-qwen35-9b-four-adapters/prewise-qwen35-9b-four-adapters-A40.zip.sha256 \
  --target /workspace/prewise-qwen35-9b-four-adapters/runtime
```

Start this compose file only on an NVIDIA GPU host with enough VRAM for the
base model, KV cache, and active LoRAs:

```bash
export ADAPTER_RUNTIME_ROOT=/workspace/prewise-qwen35-9b-four-adapters/runtime
export ADAPTER_MANIFEST_PATH=/adapters/qwen35-vllm-manifest.json
export LLM_API_KEY='replace-with-a-long-random-secret'
docker compose -f docker-compose.ai.yml up -d --build
```

Configure the application backend with:

```dotenv
LLM_PROVIDER=adapter
ADAPTER_MANIFEST_PATH=/app/server/adapters/qwen35-backend-manifest.json
ADAPTER_RUNTIME_ROOT=/workspace/prewise-qwen35-9b-four-adapters/runtime
ADAPTER_BASE_URL=https://your-private-gpu-endpoint.example/v1
ADAPTER_API_KEY=the-same-runtime-secret
LEGAL_ADAPTER_MODEL=prewise-legal-rag
```

Keep the vLLM port private. Expose it only through authenticated TLS ingress
or a private service network. The backend validates local adapter metadata and
fails closed if artifacts or the endpoint are unavailable.
