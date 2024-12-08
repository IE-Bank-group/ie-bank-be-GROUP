FROM python:3.10-slim-buster
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
EXPOSE 5001
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]