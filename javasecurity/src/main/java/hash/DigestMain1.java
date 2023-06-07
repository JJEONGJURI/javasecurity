package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;
import java.util.Set;

/*
 * 해쉬 알고리즘 예쩨
 */
public class DigestMain1 {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		byte[] plain = null;
		byte[] hash = null;
		//MessageDigest : 현재 자바단에서 처리 가능한 해쉬 알고리즘 목록
		Set<String> algorithms = Security.getAlgorithms("MessageDigest");
		System.out.println(algorithms);
		String[] algo = {"MD5","SHA-1","SHA-256","SHA-512"};
		System.out.println("해쉬값을 구할 문자열을 입력하세요");
		Scanner scan = new Scanner(System.in);
		String str = scan.nextLine();
		plain = str.getBytes(); //문자열을 byte형 배열로 만든다.
		for(String al : algo) {
			MessageDigest md = MessageDigest.getInstance(al); //hash 알고릐즘 객체
			hash = md.digest(plain); //plain : 내가 입력한거
			//여기서 하는거는 자바의 해쉬코드랑은 연관없다.
			//해쉬값 : 비트형으로 나타나서 바이트로 전해줌
			System.out.println(al + "해쉬값 크기:" + (hash.length*8) + "bits"); //512비트 => 64바이트
			
			System.out.print("해쉬값:");
			for(byte b : hash) System.out.printf("%02X",b); //16진수 2자리(1byte) 코드값으로 출력
			System.out.println();
		}
	}
}
