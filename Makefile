
default: javabuild


javabuild: 
	-mkdir -p bin
	javac -sourcepath src \
          -classpath "lib/*" \
          -d bin \
          src/cloudStorage/core/*.java    

clean:
	-rm -r bin

