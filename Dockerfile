FROM php:8.4-cli

# Install ekstensi wajib untuk Workerman
RUN docker-php-ext-install pcntl posix sockets bcmath

# Copy aplikasi kamu
WORKDIR /app
COPY ./app /app

EXPOSE 8053/udp
EXPOSE 8080

# Jalankan Workerman
CMD ["php", "index.php", "start"]