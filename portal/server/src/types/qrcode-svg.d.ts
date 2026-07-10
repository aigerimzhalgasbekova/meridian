declare module 'qrcode-svg' {
  interface Options {
    content: string;
    padding?: number;
    width?: number;
    height?: number;
    ecl?: 'L' | 'M' | 'Q' | 'H';
    join?: boolean;
  }
  class QRCode {
    constructor(options: Options | string);
    svg(): string;
  }
  export = QRCode;
}
