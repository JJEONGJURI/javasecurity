package aes;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;

/*
 * usersecurity 테이블의 내용을 출력하기
 *  이메일은 복호화하여 출력하기.
 *  1. 암호화키와 동일하게 처리해야함
 *  
 */
public class CipherMain4 {

	public static void main(String[] args) throws Exception {
		Class.forName("org.mariadb.jdbc.Driver");
		Connection conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/gdudb","gdu","1234");
		PreparedStatement pstmt = conn.prepareStatement("select userid,username,email,phoneno,birthday from usersecurity");
		ResultSet rs = pstmt.executeQuery();
		
		 ResultSetMetaData rsmd = rs.getMetaData();
		 for(int i =1; i<=rsmd.getColumnCount();i++) {
			System.out.println(rsmd.getColumnName(i)+"\t");
		 }
		 	System.out.println();
		 
		
		while(rs.next()) {
			String userid = rs.getString("userid");
			String key = CipherUtil.makehash(userid); // hash 코드
			String email = rs.getString("email");	//암호화된 내용
//			System.out.println("암호화 :" + email);
			String plainEmail = CipherUtil.decrypt(email,key);
//			System.out.println("복호화 :" +plainEmail);
			
			for(int i =1; i<=rsmd.getColumnCount();i++) {
				if(i==3) System.out.println(plainEmail+"\t");
				else System.out.print(rs.getString(i)+"\t");
			}
			System.out.println();
			

		}
		
	}

}
