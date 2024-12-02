# Use Python 3.12 as the base image
FROM python:3.12.7-bullseye

# Set working directory in the container
WORKDIR /app

# Copy application files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose port 5000
EXPOSE 5000

# Set environment variables for Flask
ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV PORT=5000
ENV DEBUGSTATUS=True
# Command to run the application
CMD ["flask", "run"]
