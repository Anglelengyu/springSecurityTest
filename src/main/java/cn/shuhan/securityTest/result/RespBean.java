package cn.shuhan.securityTest.result;

public class RespBean {

    private static Integer SUCCESS = 200;
    private static Integer ERR = 500;

    private Integer code;
    private String msg;
    private Object obj;

    public static RespBean ok(String msg, Object obj) {
        return new RespBean(SUCCESS, msg, obj);
    }

    public static RespBean error(String msg) {
        return new RespBean(ERR, msg, null);
    }

    public static RespBean ok(String msg) {
        return new RespBean(SUCCESS, msg, null);
    }

    public RespBean() {
    }

    public RespBean(Integer code, String msg, Object obj) {
        this.code = code;
        this.msg = msg;
        this.obj = obj;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getObj() {
        return obj;
    }

    public void setObj(Object obj) {
        this.obj = obj;
    }
}
