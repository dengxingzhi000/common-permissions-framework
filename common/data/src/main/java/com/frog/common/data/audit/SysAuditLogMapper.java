package com.frog.common.data.audit;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface SysAuditLogMapper extends BaseMapper<SysAuditLogPO> {
}
