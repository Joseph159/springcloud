package com.hmall.gateway.filters;

import com.hmall.gateway.config.AuthProperties;
import com.hmall.gateway.util.JwtTool;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@RequiredArgsConstructor
@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private final AuthProperties authProperties;

    private final JwtTool jwtTool;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 获取request
        ServerHttpRequest request = exchange.getRequest();
        // 无需校验, 直接放行
        if (isExclude(request.getPath().toString())){
            return chain.filter(exchange);
        }
        // 获取请求头中的token
        List<String> headers = request.getHeaders().get("authorization");
        String token = null;
        if (headers != null && !headers.isEmpty()) {
            token = headers.get(0);
        }
        Long userId = null;
        try {
            // 解析jwt令牌
            userId = jwtTool.parseToken(token);
        } catch (Exception e) {
            // 没有登陆进行拦截
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        // 将userInfo写入下游拦截器获取的信息
        String userInfo = userId.toString();
        ServerWebExchange swe = exchange.mutate().
                request(builder -> builder.header("user-info", userInfo)).build();
        return chain.filter(swe);
    }

    private boolean isExclude(String path) {
        // 遍历是否无需过滤
        for (String excludePath : authProperties.getExcludePaths()) {
            if (antPathMatcher.match(excludePath, path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        // 设置过滤器优先级
        return 0;
    }
}
