package aes;
/*
 * AES 암호화 : 대칭키 암호화 => 암호화와, 복호화에 사용되는 키가 같은 경우
 */
public class CipherMain1 {

	public static void main(String[] args) {
		String plain1 = "안녕하세요 홍길동 입니다.";
		String cipher1 = CipherUtil.encrypt(plain1);	//암호문
		System.out.println("암호문:" + cipher1);	//암호문출력. 실행시마다 다른 암호문 출력. key가 계속 변경됨
		String plain2 = CipherUtil.decrypt(cipher1);	//복호문 생성
		System.out.println("복호문:" + plain2);	//plain1 == plain2
	}

}
