import axiosAPI from "../utils/axios-api";

const setJWTToken = token => {
  if (token) {
    axiosAPI.defaults.headers.common["Authorization"] = token;
  } else {
    delete axiosAPI.defaults.headers.common["Authorization"];
  }
};

export default setJWTToken;
