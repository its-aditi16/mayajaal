FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY pyproject.toml README.md ./
COPY mayajaal ./mayajaal
RUN pip install --no-cache-dir ".[all]"
RUN useradd --create-home --uid 10001 mayajaal && mkdir -p /data && chown mayajaal /data
USER mayajaal
ENV MAYAJAAL_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "--factory", "mayajaal.demo.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
