#!/bin/bash
# Start Jupyter for Google Colab connection

cd /home/adorsatwar/Finetuning/Finetuning
source venv/bin/activate

# Start Jupyter with Colab-compatible settings
jupyter notebook \
    --port=8888 \
    --no-browser \
    --ip=0.0.0.0 \
    --NotebookApp.token='fireweave' \
    --NotebookApp.allow_origin='https://colab.research.google.com' \
    --NotebookApp.disable_check_xsrf=True
