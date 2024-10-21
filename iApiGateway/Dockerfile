FROM openjdk:17

ARG JAR_FILE=target/*.jar

ADD ${JAR_FILE} gateway-service.jar

ENTRYPOINT ["java","-jar","gateway-service.jar"]

EXPOSE 8082