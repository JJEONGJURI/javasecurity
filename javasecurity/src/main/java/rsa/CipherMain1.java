package rsa;

/*
 * 공개키 암호화 예제
 * 	RSA 알고리즘 이용 => 개인키, 공개키를 이용하여 암호화, 복호화에 사용됨.
 * 		개인키 암호화 => 공개키로 복호화 가능 => 부인방지.
 * 		공개키 암호화 => 개인키로 복호화 가능	 => 기밀분서
 * 
 */
public class CipherMain1 {

	public static void main(String[] args) {
		String plain1 = "안녕하세요 홍길동 입니다.";
		String cipher1 = CipherRSA.encrypt(plain1);
		System.out.println("암호문 :"+ cipher1);		
		String plain2 = CipherRSA.decrypt(cipher1);
		System.out.println("복호문 :"+ plain2);
		
	}

}
