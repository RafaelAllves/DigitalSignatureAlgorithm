# DigitalSignatureAlgorithm

# Create Project
mvn archetype:generate -DgroupId=com.dsa -DartifactId=DigitalSignatureAlgorithm -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false

# Compile
mvn clean compile

# Run
mvn exec:java -Dexec.mainClass="com.dsa.ECDSA"
mvn exec:java -Dexec.mainClass="com.dsa.ECDSATest"
mvn exec:java -Dexec.mainClass="com.dsa.MLDSATest"

# Algoritmo Hash - Keccak-256
Keccak-256 gera um hash de 256 bits (ou 32 bytes).
Representação hexadecimal: 64 caracteres.



$ mvn package -P linux -Dliboqs.include.dir="/usr/local/include" -Dliboqs.lib.dir="/usr/local/lib" -Dmaven.test.skip=true



mvn install:install-file -Dfile=target/liboqs-java.jar -DgroupId=org.openquantumsafe -DartifactId=liboqs-java -Dversion=1.0 -Dpackaging=jar
