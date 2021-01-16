package org.sid.secservice.sec.repo;

import org.sid.secservice.sec.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRespository extends JpaRepository<AppRole,Long> {
        AppRole findByRoleName(String rolName);
}
