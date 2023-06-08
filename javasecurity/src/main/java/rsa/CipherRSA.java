package rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class CipherRSA {
	static Cipher cipher;
	static PrivateKey priKey;
	static PublicKey pubKey;
	static {
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			//공개키(RSA) 암호화에 사용될 키 생성
			KeyPairGenerator key = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = key.genKeyPair();	//키의 쌍인 객체 저장
			priKey = keyPair.getPrivate();//개인키
			pubKey = keyPair.getPublic(); //공개키
		} catch (Exception e ) {
			e.printStackTrace();
		}
	}
	public static String encrypt(String plain1) {	//암호화
		//plain1 : 평문
		byte[] cipherMsg = new byte[1024];
		try {
			cipher.init(Cipher.ENCRYPT_MODE,priKey);	//암호화모드, 개인키
			cipherMsg = cipher.doFinal(plain1.getBytes());	//암호화
		} catch (Exception e) {
			e.printStackTrace();
		}
		return byteToHex(cipherMsg);	//16진수 문자열로 리턴
		//9A48BBC9A8EA7387DA6F7F78266436C1FEBDD088843B042570F4D0A7112609D72D69A975A6C962
	}

	private static String byteToHex(byte[] cipherMsg) {
		if(cipherMsg == null)
		return null;
		String str = "";
		for(byte b : cipherMsg) {
			str+= String.format("%02X",b);//16진수 두자리로 바꿔서 str 로 전달
		}
		return str;
	}
	//복호화 시작
	public static String decrypt(String cipher1) {
		//cipher1 : 암호문. 16진수 표현된 문자열
		byte[] plainMsg = new byte[1024];
		try {
			cipher.init(Cipher.DECRYPT_MODE, pubKey); //복호화
			plainMsg = cipher.doFinal(hexToByte(cipher1.trim()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(plainMsg).trim();	//문자열형태의 데이터로 만들어줌
	}
	//16진수 표현의 문자열 => byte[]
	private static byte[] hexToByte(String str) {
		if(str == null || str.length() < 2)
			return null;
		byte[] buf = new byte[str.length() / 2];
		for(int i=0; i<buf.length;i++) {
			buf[i] = (byte)Integer.parseInt(str.substring(i*2,i*2+2),16);
		}
		return buf;
	}

	public static void getKey() {
		// TODO Auto-generated method stub
		
	}

	public static String encrypt(String org, int menu1) {
		// TODO Auto-generated method stub
		return null;
	}

	public static String decrypt(String org, int menu1) {
		// TODO Auto-generated method stub
		return null;
	}

	
}
