package com.mykyda.mykyauth.data.repository;

import com.mykyda.mykyauth.data.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Modifying
    @Query("update RefreshToken rt set rt.revoked = true where rt.id = :id and rt.revoked = false")
    int revoke(UUID id);

    @Modifying
    @Query("update RefreshToken rt set rt.revoked = true where rt.user.id = :userId and rt.revoked = false")
    void revokeAllByUserId(Long userId);
}
