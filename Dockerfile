FROM python:3.9-slim
LABEL maintainer="Michael Macnair"
LABEL description="Query Prisma Cloud for untriaged container issues"

# Pipeline utility dependencies
# make, mypy, and pylint are for our own pipeline
# httpie and jq are for users to get API tokens
# pip is so pip doesn't complain about being old
RUN apt-get update && apt-get install --no-install-recommends -y \
    jq \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --upgrade pip poetry 

# we're already in a container, no need for venvs
RUN poetry config virtualenvs.create false

# Install the tool and its dependencies
# We can't just do a plain 'poetry install' because of https://github.com/python-poetry/poetry/issues/1382
WORKDIR /tmp/install
COPY . ./
RUN make clean && poetry install -n --no-root && make && pip install dist/*.whl

RUN useradd app --create-home
# for users who install additional tools via pip
ENV PATH="/home/app/.local/bin:${PATH}"

# cleanup

USER app:app
WORKDIR /mnt
ENTRYPOINT ["prisma-cloud-pipeline"]