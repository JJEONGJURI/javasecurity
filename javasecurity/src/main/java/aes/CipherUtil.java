package aes;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherUtil {
	private static byte[] randomKey;
	//초기화블럭(벡터)	: 첫번째 블럭에 값 제공
	//CBC 모드 : 블럭암호화시 앞블럭의 암호문이 뒤 블럭의 암호화에 영향을 줌
	//패딩방법 : 마지막블럭의 자리수를 지정된 블럭의 크기만큼 채워주는 방법을 설정
	private final static byte[] iv = new byte[] {
			(byte)0x8E,0x12,0x39,(byte)0x9,
				  0x07,0x72,0x6F,(byte)0x5A,
		    (byte)0x8E,0x12,0x39,(byte)0x9,
		    	  0x07,0x72,0x6F,(byte)0x5A};
	
	static Cipher cipher;	//암호처리 객체
	static {
		try { 
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");	// 알고리즘/블럭암호모드/패딩방법
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	public static byte[] getRandomKey(String algo) throws NoSuchAlgorithmException {
		//algo : 암호알고리즘이름 => AES 
		//keyGen : 암호 알고리즘에 맞는 키 생성을 위한 객체
		KeyGenerator keyGen = KeyGenerator.getInstance(algo);
		keyGen.init(128); //AES 알고리즘 키 크기 : 128 ~ 196 비트 크기 가능. > 키 크기가 가변적 . 보통 8의 배수형태로 들어간다
		SecretKey key = keyGen.generateKey();	//keyGen 객체에 설정된 내용으로 키 생성
		return key.getEncoded();	//byte[] 형태로 리턴
	}
	public static String encrypt(String plain) { //return String 
		//plain : 암호화를 위한 평문 데이터
		byte [] cipherMsg = new  byte [1024];
		try {
			//대칭키 : 암호화키 == 복호화키
			randomKey = getRandomKey("AES");
			//AES 알고리즘에서 사용할 Key 객체로 생성
			Key key = new SecretKeySpec(randomKey, "AES");
			//CBC 방식에서 사용할 초기화 백터값을 설정
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			//Cipher.Encrypt_MODE(암호화처리) cipher객체에 키,IV 설정
			cipher.init(Cipher.ENCRYPT_MODE, key,paramSpec); //암호화를 위한 cipher 객체
			cipherMsg = cipher.doFinal(plain.getBytes());	//암호화 실행
			//cipherMsg  배열의 형태로 들어옴
		} catch(Exception e) {
			e.printStackTrace();
		}
		return byteToHex(cipherMsg).trim();	//문자열로 암호문 리턴
		//byte[] 숫자인데 우리눈으로 볼수없고 ASKII 값으로 봄
		//byte[] 데이터 =>  16진수값을 가진 문자열 형태로 변형 시켜주는 함수(byteToHex)
	}
	private static String byteToHex(byte[] cipherMsg) {
		if(cipherMsg == null) return null;
		String str = "";
		for(byte b : cipherMsg) {
			str += String.format("%02X", b);
			//각 바이트를 2자리 16진수로 생성
		}
		return str;
	}
	//cipherMsg :  C4821104EF48278344D4FACE932E0D9F38F3C16CCCA197A
	//암호화된 데이터를 평문으로 리턴 : decrypt 함수
	public static String decrypt(String cipherMsg) {
		byte[] plainMsg = new byte[1024];
		try {
			Key key = new SecretKeySpec(randomKey,"AES"); // 암호화에 사용된키 복호화에 그대로 넣어서 사용
			//randomKey : 암호화에서 사용된 키값
			//AES알고리즘에서 사용할 키 객체로 생성
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			//CBC 모드에서 사용할 IV 설정
			cipher.init(Cipher.DECRYPT_MODE,key,paramSpec);
			//복호화 객체 설정
			//Cipher.DECRYPT_MODE : 복호화 기능 
			plainMsg = cipher.doFinal(hexToByte(cipherMsg.trim())); //복호화 실행
			//byte 배열로 만들어짐
		} catch(Exception e) {
			e.printStackTrace();
		}
		return new String(plainMsg).trim();	//byte[] 형태의 평문 => 문자열 
	}
	//암호화된 문자열 => byte[] 값 
	private static byte[] hexToByte(String str) {
		//str : C4821104EF48278344D4FACE932E0D9F38F3C16CCCA...
		if(str ==null || str.length() <2) 
			return null;	//잘봇된 데이터.
		int len = str.length() /2;	//2개의 문자열데이터가 한 바이트
		byte[] buf = new byte[len]; //7,...
		for(int i = 0; i<len ; i++) {
			buf[i] = (byte) Integer.parseInt(str.substring(i*2, i * 2 +2), 16);
		}
		return buf;
	}
	public static String encrypt(String plain1, String key) {
		byte[] cipherMsg = new byte[1024];
		try {
										// 	byte[]      알고리즘
			Key genKey = new SecretKeySpec(makeKey(key),"AES");	//128 비트 크기
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, genKey, paramSpec);
			cipherMsg = cipher.doFinal(plain1.getBytes()); //암호문
		} catch(Exception e) {
			e.printStackTrace();
		}
		return byteToHex(cipherMsg);
	}
	//AES 알고리즘의 키 크기 : 128비트 => 16바이트 (16*8비트)
	//					 128비트의 크기로 변경
	private static byte[] makeKey(String key) {
		//key : abc1234567
		int len = key.length();//len : 10자리
		char ch='A';
		for(int i=len; i<16; i++) {
			//16바이트로 생성
			key += ch++;
			//abc1234567ABCDEF
		}
		return key.substring(0,16).getBytes();
		//16바이트로 생성		
	}
	public static String decrypt(String cipher1, String key) {
		byte[] plainMsg = new byte[1024];
		try {
			Key genKey = new SecretKeySpec(makeKey(key),"AES");
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, genKey, paramSpec); //key 값 다르면 에러 
			plainMsg = cipher.doFinal(hexToByte(cipher1.trim()));
		} catch(Exception e) {
			e.printStackTrace();
		}
		return new String(plainMsg).trim();
	}
	public static String makehash(String msg) throws Exception  {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] plain = msg.getBytes();
		byte[] hash = md.digest(plain);
		return byteToHex(hash);
	}
			
}
