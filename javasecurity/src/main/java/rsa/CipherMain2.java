package rsa;

import java.util.Scanner;

//공개키 암호화의 키를 저장하고 키를 이용하여 암호화 복호화 하기
public class CipherMain2 {
	public static void main(String[] args) {
		CipherRSA.getKey();	//개인키, 공개키 파일로 각각 저장
		Scanner scan = new Scanner(System.in);
		String str1 = null;
		String str2 = null;
		String org = null;
		String result = null;
		while(true) {
			System.out.println("문서의 종류 선택(1.기밀문서, 2.본인작성표시, 9.종료)");
			//1. 기밀분서 : 공개키로 암호화. 개인키로 복호화
			//2. 본인작성표시 : 개인키로 암호화. 공개키로 복호화 (부인방지)
			int menu1 = scan.nextInt();
			if(menu1 == 9) break;
			System.out.println("(1.암호화, 2.복호화)");
			int menu2 = scan.nextInt();
			str1 = (menu1==1)?"기밀문서":"본인작성표시";
			str2 = (menu2==1)?"암호":"복호";
			System.out.println(str1+" " + str2 + "를 위한 내용을 입력하세요.");
			org = scan.next();	//암호, 복호화에 필요한 데이터 입력
			//만약 기밀문서라면 encrypt : 공개키로 암호화 , decrypt : 개인키로 복호화
			result = (menu2==1)?CipherRSA.encrypt(org,menu1) :	//암호화
								CipherRSA.decrypt(org,menu1);	//복호화
			System.out.println("===" + str2 + "===");
			System.out.println(result);
		}
	}

}
