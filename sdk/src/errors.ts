export class SekishoError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'SekishoError'
    this.status = status
  }
}
