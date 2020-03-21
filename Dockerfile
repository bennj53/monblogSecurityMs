FROM openjdk:8-jdk-alpine
COPY ./target/sec-service-0.0.1-SNAPSHOT.jar /usr/app/
WORKDIR /usr/app/
RUN sh -c 'touch sec-service-0.0.1-SNAPSHOT.jar'
ENTRYPOINT ["java","-jar","sec-service-0.0.1-SNAPSHOT.jar"]