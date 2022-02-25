/* --------------------------------------------------------------------------------
 * File: Server.java
 * Subject : NetworkSecurity - AjouUniversity
 * Developer: 201820697 Sojeong Kim
 * Date: 2021.06.13
 * -------------------------------------------------------------------------------- */
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

public class Server {

    public static void main(String[] args) throws IOException {

        ServerSocket Server_Socket = null;
        Socket Client_Socket = null;


        //서버 생성 및 클라이언트 접속
        try {
            //서버 생성
            Server_Socket = new ServerSocket(10101);
            //클라이언트 접속
            Client_Socket = Server_Socket.accept();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //데이터 스트림 생성
        ObjectOutputStream Server_MSG = new ObjectOutputStream(Client_Socket.getOutputStream());
        ObjectInputStream Client_MSG = new ObjectInputStream(Client_Socket.getInputStream());

        //RSA 및 AES 설정
        byte[] Decrypted_AES_Key = new byte[0];
        byte[] Decrypted_AES_IV = new byte[0];
        try {
            System.out.println("> Creating RSA key Pair...");
            //RSA gernerator
            KeyPairGenerator KeyPair_Generator = KeyPairGenerator.getInstance("RSA");
            KeyPair_Generator.initialize(2048);
            //RSA public key, private key
            KeyPair Key_Pair = KeyPair_Generator.genKeyPair();
            PublicKey Public_Key = Key_Pair.getPublic();
            PrivateKey Private_Key = Key_Pair.getPrivate();
            //RSA public key, private key base64 출력
            byte[] Byte_PublicKey = Public_Key.getEncoded();
            byte[] Byte_PrivateKey = Private_Key.getEncoded();
            System.out.println("[Public Key]: " + Base64.getEncoder().encodeToString(Byte_PublicKey));
            System.out.println("-----------------------------------------------------------------------------------");
            System.out.println("[Private Key]: " + Base64.getEncoder().encodeToString(Byte_PrivateKey));
            //클라이언트에게 RSA public key 전송
            Server_MSG.writeObject(Public_Key);
            Server_MSG.flush();

            //클라이언트가 보낸 암호화된 AES secret key 받음
            byte[] Encrypted_AES_Key = (byte[]) Client_MSG.readObject();
            System.out.println("\n> [Received AES Key] : " + Base64.getEncoder().encodeToString(Encrypted_AES_Key));
            System.out.println("-----------------------------------------------------------------------------------");
            //클라이언트가 보낸 암호화된 AES IV 받음
            byte[] Encrypted_AES_IV = (byte[]) Client_MSG.readObject();
            System.out.println("> [Received AES IV] : " + Base64.getEncoder().encodeToString(Encrypted_AES_IV));
            System.out.println("-----------------------------------------------------------------------------------");
            //암호화된 AES secret key를 RSA private key로 복호화
            Cipher cipher_AES_Key = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher_AES_Key.init(Cipher.DECRYPT_MODE, Private_Key);
            Decrypted_AES_Key = cipher_AES_Key.doFinal(Encrypted_AES_Key);
            //복호화한 AES secret key base64 출력
            System.out.println("[Decrypted AES Key] : " + Base64.getEncoder().encodeToString(Decrypted_AES_Key));
            System.out.println("-----------------------------------------------------------------------------------");
            //암호화된 AES IV를 RSA private key로 복호화
            Cipher cipher_AES_IV = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher_AES_IV.init(Cipher.DECRYPT_MODE, Private_Key);
            Decrypted_AES_IV = cipher_AES_IV.doFinal(Encrypted_AES_IV);
            //복호화한 AES IV base64 출력
            System.out.println("[Decrypted IV] : " + Base64.getEncoder().encodeToString(Decrypted_AES_IV)+"\n");
        } catch (Exception e) {
        }


        //서버 -> 클라이언트 Thread
        Scanner in = new Scanner(System.in);
        byte[] finalDecrypted_AES_Key = Decrypted_AES_Key;
        byte[] finalDecrypted_AES_IV = Decrypted_AES_IV;
        Thread Server_thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        //서버 -> 클라이언트 메시지 입력
                        System.out.print("\n>");
                        String msg = in.nextLine();

                        //AES secret key, IV 초기화
                        SecretKeySpec SecretKey_Spec = new SecretKeySpec(finalDecrypted_AES_Key, 0, finalDecrypted_AES_Key.length, "AES");
                        IvParameterSpec IvParameter_Spec = new IvParameterSpec(finalDecrypted_AES_IV);
                        //보낼 메시지(msg) AES-CBC 암호화
                        Cipher cipher_AES_Data = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher_AES_Data.init(Cipher.ENCRYPT_MODE, SecretKey_Spec, IvParameter_Spec);
                        byte[] Encrypted_msg = cipher_AES_Data.doFinal(msg.getBytes(StandardCharsets.UTF_8));

                        //클라이언트에게 암호화된 메시지(Encrypted_msg) 보냄
                        Server_MSG.writeObject(Encrypted_msg);
                    } catch (Exception e) {
                    }
                }
            }
        });
        Server_thread.start();


        //클라이언트 -> 서버 Thread
        Socket finalClient_Socket = Client_Socket;
        ServerSocket finalServer_Socket = Server_Socket;
        Thread Client_Thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        //클라이언트 -> 서버 메시지 받음
                        byte[] Encrypted_msg = (byte[]) Client_MSG.readObject();

                        //AES secret key, IV 초기화
                        SecretKeySpec SecretKey_Spec = new SecretKeySpec(finalDecrypted_AES_Key, 0, finalDecrypted_AES_Key.length, "AES");
                        IvParameterSpec IvParameter_Spec = new IvParameterSpec(finalDecrypted_AES_IV);
                        //받은 암호화된 메시지(Encrypted_msg) AES-CBC 복호화
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, SecretKey_Spec, IvParameter_Spec);
                        byte[] msg = cipher.doFinal(Encrypted_msg);

                        //Timestamp를 위한 작업..
                        Date date_now = new Date(System.currentTimeMillis());
                        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                        String today = date_format.format(date_now);

                        //exit 문구 검사 용 bytep[] msg -> String msg_String 제작
                        String msg_String = new String(msg, "UTF-8");

                        //exit 문구 검사
                        if (msg_String.equals("exit")) {
                            //통신 그만 하자~
                            //복호화한, 받은 메시지(msg) 정상 출력
                            System.out.println("Received : " + "\"" + msg_String + "\" " + "[" + today + "]");
                            //받은 메시지(Encrypted_msg) base64 출력
                            System.out.println("Encrypted Message :" + "\"" + Base64.getEncoder().encodeToString(Encrypted_msg));

                            Cipher cipher_AES_Data = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher_AES_Data.init(Cipher.ENCRYPT_MODE, SecretKey_Spec, IvParameter_Spec);
                            byte[] Encrypted_msg_new = cipher_AES_Data.doFinal(msg_String.getBytes(StandardCharsets.UTF_8));
                            Server_MSG.writeObject(Encrypted_msg_new);
                            break;
                        }
                        else{
                            //복호화한, 받은 메시지(msg) 정상 출력
                            System.out.println("Received : " + "\"" + msg_String + "\" " + "[" + today + "]");
                            //받은 메시지(Encrypted_msg) base64 출력
                            System.out.println("Encrypted Message :" + "\"" + Base64.getEncoder().encodeToString(Encrypted_msg) + "\n");
                            System.out.print("\n>");
                        }

                    } catch (Exception e) {
                    }
                }
                //통신 종료 close
                System.out.println("Connection closed.");
                try {
                    Server_MSG.close();
                    Client_MSG.close();
                    finalClient_Socket.close();
                    finalServer_Socket.close();
                    System.exit(0);
                } catch (Exception e) {
                }
            }
        });
        Client_Thread.start();
    }
}
