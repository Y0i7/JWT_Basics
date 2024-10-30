package com.JWTPractice.Security_Practice.Security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JWTBase64Practice {
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static byte[] createBinaryToken(String username) {
        
        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(SECRET_KEY)
                .compact();

        
        return token.getBytes();
    }

    public static Claims decodeBinaryToken(byte[] binaryToken) {
        try {
            
            String tokenString = new String(binaryToken);

            
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(tokenString)
                    .getBody();
        } catch (JwtException e) {
            System.out.println("Token inválido: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] args) {
        byte[] binaryToken = createBinaryToken("Danielito");
        System.out.print("Token en binario generado: ");
        for (byte b : binaryToken) {
            System.out.print(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0') + " ");
        }
        System.out.println();

        Claims claim = decodeBinaryToken(binaryToken);
        if (claim != null) {
            System.out.println("Datos del Token:");
            System.out.println("Usuario: " + claim.getSubject());
            System.out.println("Emitido en: " + claim.getIssuedAt());
            System.out.println("Expira en: " + claim.getExpiration());
        } else {
            System.out.println("No se pudieron obtener los datos del Token");
        }
    }
}
