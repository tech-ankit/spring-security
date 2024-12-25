package com.security.service;

import com.security.entity.AppUser;
import com.security.entity.RefreshTokenEntity;
import com.security.payload.AuthResponseDto;
import com.security.payload.TokenType;
import com.security.payload.UserInfoMapper;
import com.security.payload.UserRegistrationDto;
import com.security.repository.RefreshTokenEntityRepository;
import com.security.repository.UserRepository;
import com.security.util.JwtTokenGenerator;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenEntityRepository refreshTokenRepo;
    private final UserInfoMapper userInfoMapper;
    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        try
        {
            AppUser userInfoEntity = userInfoRepo.findByEmail(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found",authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND,"USER NOT FOUND ");});


            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
            //Let's save the refreshToken as well
            saveUserRefreshToken(userInfoEntity,refreshToken);
            //Creating the cookie
            creatRefreshTokenCookie(response,refreshToken);
            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }

    private void saveUserRefreshToken(AppUser userInfoEntity, String refreshToken) {
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfoEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    private Cookie creatRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token",refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60 ); // in seconds
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }

    public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {

        if(!authorizationHeader.startsWith(TokenType.Bearer.name())){
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please verify your token type");
        }
        final String refreshToken = authorizationHeader.substring(7);
        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(tokens-> !tokens.isRevoked())
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Refresh token revoked"));

        AppUser userInfoEntity = refreshTokenEntity.getUser();
        Authentication authentication =  createAuthenticationObject(userInfoEntity);

        //Use the authentication object to generate new accessToken as the Authentication object that we will have may not contain correct role.
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return  AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
    }

    private static Authentication createAuthenticationObject(AppUser userInfoEntity) {
        // Extract user details from UserDetailsEntity
        String username = userInfoEntity.getEmail();
        String password = userInfoEntity.getPassword();
        String roles = userInfoEntity.getRole();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }

    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,
                                        HttpServletResponse httpServletResponse) {
        try{
            log.info("[AuthService:registerUser]User Registration Started with :::{}",userRegistrationDto);

            Optional<AppUser> user = userInfoRepo.findByEmail(userRegistrationDto.userEmail());
            if(user.isPresent()){
                throw new Exception("User Already Exist");
            }

            AppUser userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
            Authentication authentication = createAuthenticationObject(userDetailsEntity);


            // Generate a JWT token
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            AppUser savedUserDetails = userInfoRepo.save(userDetailsEntity);
            saveUserRefreshToken(userDetailsEntity,refreshToken);

            creatRefreshTokenCookie(httpServletResponse,refreshToken);

            log.info("[AuthService:registerUser] User:{} Successfully registered",savedUserDetails.getUserName());
            return   AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(savedUserDetails.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:registerUser]Exception while registering the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }
    }
}
