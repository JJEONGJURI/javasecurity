package aes;
//암호화된 파일을 복호화 하여 p2.txt 파일에 저장하기
public class CipherMain6 {

	public static void main(String[] args) {
		CipherUtil.decryptFile("c.sec","p2.txt");
	}

}
