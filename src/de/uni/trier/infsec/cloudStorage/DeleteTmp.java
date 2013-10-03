package de.uni.trier.infsec.cloudStorage;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

public class DeleteTmp {
	public static void main(String[] args) throws IOException{
		
		Path dir = FileSystems.getDefault().getPath(Params.PKI_DATABASE);
		try{
			Files.delete(dir);
		}catch (NoSuchFileException e){
			System.out.println(e.toString());
		}
		dir = FileSystems.getDefault().getPath(Params.PATH_STORAGE);
		Files.walkFileTree(dir, new FileVisitor<Path>() {
			 @Override
			 public FileVisitResult postVisitDirectory(Path dir, IOException exc)
	                    throws IOException {
	                
	                System.out.println("Deleting directory: "+ dir);
	                Files.delete(dir);
	                return FileVisitResult.CONTINUE;
	            }
	 
	            @Override
	            public FileVisitResult preVisitDirectory(Path dir,
	                    BasicFileAttributes attrs) throws IOException {
	                return FileVisitResult.CONTINUE;
	            }
	 
	            @Override
	            public FileVisitResult visitFile(Path file,
	                    BasicFileAttributes attrs) throws IOException {
	                System.out.println("Deleting file: " + file);
	                Files.delete(file);
	                return FileVisitResult.CONTINUE;
	            }
	 
	            @Override
	            public FileVisitResult visitFileFailed(Path file, IOException exc)
	                    throws IOException {
	                System.out.println(exc.toString());
	                return FileVisitResult.CONTINUE;
	            }
	        });
	}
	
	public static void out(String s){
		System.out.println(s);
	}
}
