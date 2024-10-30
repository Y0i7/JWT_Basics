package com.JWTPractice.Security_Practice.Security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JWTPractice {
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static String createToken(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+60000))
                .signWith(SECRET_KEY)
                .compact();

    }

    public static Claims decodeToken(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SignatureException e) {
            System.out.println("Token inválido: " + e.getMessage());
            return null;
        } catch (ExpiredJwtException e) {
            System.out.println("Token expirado: " + e.getMessage());
            return null;
        } catch (MalformedJwtException e) {
            System.out.println("Token mal formado: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.out.println("Error desconocido: " + e.getMessage());
            return null;
        }
    }


    public static void main(String[] args) {
        String token = createToken("user123");
        System.out.println("Token JWT generado: " + token);

        Claims claim = decodeToken(token);
        if (claim != null){
            System.out.println("Datos del Token: "+claim);
            System.out.println("Usuario: " + claim.getSubject());
            System.out.println("Emitido en: " + claim.getIssuedAt());
            System.out.println("Expira en: " + claim.getExpiration());
        }else {
            System.out.println("No se pudieron obtener los datos del Token");
        }
    }
}


