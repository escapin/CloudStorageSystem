BCPROV_t=jdk16
BCPROV_v=1.46
JAVA_PARSER=1.0.8
SQLJET=1.1.10
SQLITE=3.21.0
JUNIT=4.12
ANTL_RUNTIME=3.4
BEANSBINDING=1.2.1
SWING=5.0

default: libdownload javabuild

libdownload:
	-mkdir -p lib
	wget -P lib -nc http://central.maven.org/maven2/org/bouncycastle/bcprov-${BCPROV_t}/${BCPROV_v}/bcprov-${BCPROV_t}-${BCPROV_v}.jar
	wget -P lib -nc http://central.maven.org/maven2/com/google/code/javaparser/javaparser/$(JAVA_PARSER)/javaparser-$(JAVA_PARSER).jar
	wget -P lib -nc http://central.maven.org/maven2/org/tmatesoft/sqljet/sqljet/$(SQLJET)/sqljet-$(SQLJET).jar
	wget -P lib -nc http://central.maven.org/maven2/org/xerial/sqlite-jdbc/$(SQLITE)/sqlite-jdbc-$(SQLITE).jar
	wget -P lib -nc http://central.maven.org/maven2/junit/junit/$(JUNIT)/junit-$(JUNIT).jar
	wget -P lib -nc http://central.maven.org/maven2/org/antlr/antlr-runtime/$(ANTL_RUNTIME)/antlr-runtime-$(ANTL_RUNTIME).jar
	wget -P lib -nc http://central.maven.org/maven2/org/jdesktop/beansbinding/$(BEANSBINDING)/beansbinding-$(BEANSBINDING).jar
	wget -P lib -nc http://central.maven.org/maven2/com/miglayout/miglayout-swing/$(SWING)/miglayout-swing-$(SWING).jar

javabuild: 
	-mkdir -p bin
	javac -sourcepath src \
          -classpath "lib/*" \
          -d bin \
          src/tests/*.java \
          src/cloudStorage/app/*.java

clean:
	cd bin; java -cp ".:../lib/*" cloudStorage.app.DeleteLocalFiles
	-rm -r bin

cleanall: clean
	-rm -r lib

