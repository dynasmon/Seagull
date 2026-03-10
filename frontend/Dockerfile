# ===== Build stage =====
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ===== Runtime stage =====
# Use unprivileged nginx so startup does not require chown/chmod on cache dirs.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# Nginx config (SPA + /api reverse proxy)
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

# Static build
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
