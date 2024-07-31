FROM public.ecr.aws/docker/library/python:3.12.4-slim

RUN apt-get update && apt-get install -y \
    zip \
    unzip \
    build-essential \
    libpoppler-cpp-dev \
    pkg-config python3-dev && \
    apt-get clean && rm -rf /var/cache/apt/lists && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

ENV PATH_CWD=/workspace \
    PLATFORM=manylinux2014_x86_64

WORKDIR /workspace

COPY scripts/lambda-build/create-package.sh /workspace/scripts/lambda-build/create-package.sh
COPY lambda_code /workspace/lambda_code
COPY utils /workspace/utils


RUN chmod +x /workspace/scripts/lambda-build/create-package.sh

CMD ["/workspace/scripts/lambda-build/create-package.sh"]