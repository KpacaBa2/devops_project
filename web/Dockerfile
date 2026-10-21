FROM nginx:1.27-alpine
RUN sed -i 's/listen       80;/listen       3080;/g' /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY src /usr/share/nginx/html/src
EXPOSE 3080
