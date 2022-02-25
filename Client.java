/* --------------------------------------------------------------------------------
 * File: Client.java
 * Subject : NetworkSecurity - AjouUniversity
 * Developer: 201820697 Sojeong Kim
 * Date: 2021.06.13
 * -------------------------------------------------------------------------------- */
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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

public class Client {


    public static void main(String[] args) throws IOException {

        Socket Client_Socket = null;
        SecretKey Secret_Key = null;
        IvParameterSpec IvParameter_Spec = null;

        boolean check = false;
        //서버 접속
        while(!check) {
            try {
                //클라이언트 -> 서버 접속
                Client_Socket = new Socket("127.0.0.1", 10101);
            } catch (IOException e) {
            }
            if(Client_Socket!=null) break;
        }


        //데이터 스트림 생성
        ObjectOutputStream Client_MSG = new ObjectOutputStream(Client_Socket.getOutputStream());
        ObjectInputStream Server_MSG = new ObjectInputStream(Client_Socket.getInputStream());

        //RSA 및 AES 설정
        try {
            //서버가 보낸 public key 받음
            PublicKey Public_Key = (PublicKey)Server_MSG.readObject();
            //RSA public key base64 출력
            byte[] Byte_PublicKey = Public_Key.getEncoded();
            System.out.println("\n> [Received Public Key]: " + Base64.getEncoder().encodeToString(Byte_PublicKey)+"\n");

            System.out.println("Creating AES-256 Key...\n");
            //AES gernerator
            KeyGenerator Key_Generator = KeyGenerator.getInstance("AES");
            Key_Generator.init(256);
            //AES secret key 생성
            Secret_Key = Key_Generator.generateKey();
            //AES radom IV 생성
            SecureRandom random = new SecureRandom();
            byte[] ivData = new byte[16];
            random.nextBytes(ivData);
            IvParameter_Spec = new IvParameterSpec(ivData);
            //AES secret key, IV base64 출력
            byte[] Byte_SecretKey = Secret_Key.getEncoded();
            System.out.println("[AES 256 Key]: "+Base64.getEncoder().encodeToString(Byte_SecretKey));
            System.out.println("-----------------------------------------------------------------------------------");
            System.out.println("[AES 256 IV]: "+Base64.getEncoder().encodeToString(IvParameter_Spec.getIV()));
            System.out.println("-----------------------------------------------------------------------------------");
            //AES secret key를 RSA public key로 암호화
            Cipher cipher_AES_Key = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher_AES_Key.init(Cipher.ENCRYPT_MODE, Public_Key);
            byte[] Encrypted_AES_Key = cipher_AES_Key.doFinal(Byte_SecretKey);
            //암호화된 AES secret key base64 출력
            System.out.println("[Encrypted AES Key] : "+Base64.getEncoder().encodeToString(Encrypted_AES_Key));
            System.out.println("-----------------------------------------------------------------------------------");
            //AES IV를 RSA public key로 암호화
            Cipher cipher_AES_IV = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher_AES_IV.init(Cipher.ENCRYPT_MODE, Public_Key);
            byte[] Encrypted_AES_IV = cipher_AES_IV.doFinal(IvParameter_Spec.getIV());
            //암호화된 AES IV base64 출력
            System.out.println("[Encrypted AES IV] : "+Base64.getEncoder().encodeToString(Encrypted_AES_IV)+"\n");

            //서버에게 암호화된 AES secret key, IV 전송
            Client_MSG.writeObject(Encrypted_AES_Key);
            Client_MSG.flush();
            Client_MSG.writeObject(Encrypted_AES_IV);
            Client_MSG.flush();
        }catch (Exception e) {
        }

        //클라이언트 -> 서버 Thread
        Scanner in = new Scanner(System.in);
        SecretKey finalSecret_Key = Secret_Key;
        IvParameterSpec finalIvParameter_Spec = IvParameter_Spec;
        Thread Client_Thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        //클라이언트 -> 서버 메시지 입력
                        System.out.print("\n>");
                        String msg = in.nextLine();

                        //보낼 메시지(msg) AES-CBC 암호화
                        Cipher cipher_AES_Data = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher_AES_Data.init(Cipher.ENCRYPT_MODE, finalSecret_Key, finalIvParameter_Spec);
                        byte[] Encrypted_msg = cipher_AES_Data.doFinal(msg.getBytes(StandardCharsets.UTF_8));

                        //서버에게 암호화된 메시지(Encrypted_msg) 보냄
                        Client_MSG.writeObject(Encrypted_msg);
                    }catch (Exception e) {
                    }
                }
            }
        });
        Client_Thread.start();


        //서버 -> 클라이언트 Thread
        Socket finalClient_Socket = Client_Socket;
        Thread Server_Thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        //서버 -> 클라이언트 메시지 받음
                        byte[] Encrypted_msg = (byte[])Server_MSG.readObject();

                        //받은 암호화된 메시지(Encrypted_msg) AES-CBC 복호화
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, finalSecret_Key, finalIvParameter_Spec);
                        byte[] msg = cipher.doFinal(Encrypted_msg);

                        //Timestamp를 위한 작업..
                        Date date_now = new Date(System.currentTimeMillis());
                        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                        String today = date_format.format(date_now);

                        //byte[] msg -> String msg_String
                        String msg_String = new String(msg,"UTF-8");

                        //exit 문구 검사
                        if(msg_String.equals("exit")) {
                            //통신 그만 하자~
                            //복호화한, 받은 메시지(msg) 정상 출력
                            System.out.println("Received : " + "\"" + msg_String + "\" " + "[" + today + "]");
                            //받은 메시지(Encrypted_msg) base64 출력
                            System.out.println("Encrypted Message :"+ "\""+Base64.getEncoder().encodeToString(Encrypted_msg));

                            Cipher cipher_AES_Data = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher_AES_Data.init(Cipher.ENCRYPT_MODE, finalSecret_Key, finalIvParameter_Spec);
                            byte[] Encrypted_msg_new = cipher_AES_Data.doFinal(msg_String.getBytes(StandardCharsets.UTF_8));
                            Client_MSG.writeObject(Encrypted_msg_new);
                            break;
                        }
                        else{
                            //통신 계속 하자~
                            //복호화한, 받은 메시지(msg) 정상 출력
                            System.out.println("Received : " + "\"" + msg_String + "\" " + "[" + today + "]");
                            //받은 메시지(Encrypted_msg) base64 출력
                            System.out.println("Encrypted Message :"+ "\""+Base64.getEncoder().encodeToString(Encrypted_msg)+"\n");
                            System.out.print("\n>");

                        }


                    }catch (Exception e) {
                    }
                }
                //통신 종료 close
                System.out.println("Connection closed.");
                try {
                    Server_MSG.close();
                    Client_MSG.close();
                    finalClient_Socket.close();
                    System.exit(0);
                }catch (Exception e) {
                }
            }
        });
        Server_Thread.start();
    }
}
