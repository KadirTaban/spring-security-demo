FROM openjdk:17-jdk-slim
WORKDIR /app
EXPOSE 8080

ARG JAR_FILE=/target/*.jar

COPY ${JAR_FILE} /app/app.jar

CMD ["java", "-jar", "app.jar"]
