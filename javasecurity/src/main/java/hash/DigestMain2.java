package hash;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/*
 * usersecurity 생성하기
 * 1. usersecurity 테이블 생성
 * 	  useraccount 테이블과 같은 내용의 테이블
 * 	  		CREATE TABLE usersecurity AS SELECT * FROM useraccount
 *	  		SELECT * FROM usersecurity
 * 2. usersecurity 테이블의 password 컬럼의 길이를 300으로 변경
 *   		 ALTER TABLE usersecurity MODIFY COLUMN PASSWORD VARCHAR(300) NOT NULL
 * 3. userid 컬럼을 기본키로 설정하기
 *   		 ALTER TABLE usersecurity ADD constraint PRIMARY KEY (userid)
 * 
 *
 * useraccount 테이블을 읽어서 usersecurity 테이블의 password 컬럼을 sha256 알고리즘을 이용하여 해쉬값으로 지정하기
 */
public class DigestMain2 {

	public static void main(String[] args) throws Exception{
		Class.forName("org.mariadb.jdbc.Driver");
		Connection conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/gdudb","gdu","1234");
		PreparedStatement pstmt = conn.prepareStatement("select userid, password from useraccount");
		ResultSet rs = pstmt.executeQuery();
		while(rs.next()) {
			String id = rs.getString("userid");
			String pass = rs.getString("password");
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			String hashpass = "";
			byte[] plain = pass.getBytes();
			byte[] hash = md.digest(plain);
			for(byte b : hash) hashpass += String.format("%02X",b);
			pstmt.close();
			pstmt = conn.prepareStatement("update usersecurity set password=? where userid=?");
			pstmt.setString(1, hashpass);
			pstmt.setString(2,id);
			pstmt.executeUpdate();
		}
	}
}
